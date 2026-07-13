// =====================================================
// pairing_provider.h — Interface genérica de pareamento
// ─────────────────────────────────────────────────
// v2: PROVISIONING_WIFI, WAITING_CLOUD_ACTIVATION e FETCHING_LOCAL_KEY
// implementados, usando provisioning_ap_mode.h, tuya_discovery.h e
// tuya_cloud_client.h.
//
// Requer, definidos em main.cpp (ou em algum header incluído antes
// deste), pelo menos:
//   extern String TOPIC_PAIRING;
//   extern void mqttPublishDoc(const char* topic, JsonDocument& doc);
//   extern TuyaCloud::Credentials tuyaCloudCreds;
// =====================================================

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include "tuya_devices.h"
#include "provisioning_ap_mode.h"
#include "tuya_discovery.h"
#include "tuya_cloud_client.h"
#include <ArduinoJson.h>

// Definidos em main.cpp — ver comentário acima.
extern String TOPIC_PAIRING;
extern void mqttPublishDoc(const char* topic, JsonDocument& doc);
extern TuyaCloud::Credentials tuyaCloudCreds;

enum class PairingStep : uint8_t {
    IDLE,
    SCANNING,
    WAITING_WIFI_CREDS,
    PROVISIONING_WIFI,
    WAITING_CLOUD_ACTIVATION,
    FETCHING_LOCAL_KEY,
    DONE,
    FAILED
};

struct PairingResult {
    bool  ok;
    char  deviceId[24];
    char  ip[16];
    uint8_t localKey[16];
    IotProtocol protocol;
    char  errorMsg[64];
};

class PairingProvider {
public:
    virtual ~PairingProvider() {}
    virtual bool begin() = 0;
    virtual void poll() = 0;
    virtual PairingStep currentStep() const = 0;
    virtual PairingResult result() const = 0;
    virtual void submitWifiCredentials(const char* ssid, const char* pass) = 0;
};

// =====================================================
// Implementação Tuya
// =====================================================

class TuyaPairingProvider : public PairingProvider {
public:
    bool begin() override {
        step = PairingStep::SCANNING;
        candidateCount = 0;
        provisionAttempted = false;
        discoveryStartMs = 0;
        Serial.println("[PAIR][TUYA] Procurando AP de pareamento (SmartLife-XXXX)...");
        WiFi.scanNetworks(true, true); // assíncrono — não bloqueia
        return true;
    }

    void poll() override {
        switch (step) {
            case PairingStep::SCANNING: pollScanning(); break;
            case PairingStep::WAITING_WIFI_CREDS: /* aguarda submitWifiCredentials() */ break;
            case PairingStep::PROVISIONING_WIFI: pollProvisioning(); break;
            case PairingStep::WAITING_CLOUD_ACTIVATION:
                // Se o device já foi previamente cadastrado no seu projeto
                // Tuya (via app oficial, uma vez), não precisa esperar
                // "ativação" separada — pular direto pra achar ele no LAN.
                step = PairingStep::FETCHING_LOCAL_KEY;
                discoveryStartMs = millis();
                break;
            case PairingStep::FETCHING_LOCAL_KEY: pollFetchingKey(); break;
            default: break;
        }
    }

    PairingStep currentStep() const override { return step; }
    PairingResult result() const override { return lastResult; }

    void submitWifiCredentials(const char* ssid, const char* pass) override {
        strncpy(homeSsid, ssid, sizeof(homeSsid) - 1);
        strncpy(homePass, pass, sizeof(homePass) - 1);
        step = PairingStep::PROVISIONING_WIFI;
    }

    // Específico da Tuya (não faz parte da interface genérica): escolhe
    // qual AP candidato usar, caso o scan tenha achado mais de um.
    void selectDevice(const char* deviceSsid) {
        strncpy(chosenDeviceSsid, deviceSsid, sizeof(chosenDeviceSsid) - 1);
        step = PairingStep::WAITING_WIFI_CREDS;
        Serial.printf("[PAIR][TUYA] Device selecionado: %s\n", chosenDeviceSsid);
    }

    // Cancela um pareamento em andamento, seja qual for o passo atual.
    // Não desfaz nada que já tenha sido enviado ao device (ex: se já
    // passou de PROVISIONING_WIFI, o device pode já estar tentando
    // conectar na rede nova — só paramos de tentar descobrir a local_key).
    void cancel() {
        Serial.println("[PAIR][TUYA] ⏹️ Pareamento cancelado pelo usuário");
        step = PairingStep::IDLE;
        candidateCount = 0;
        provisionAttempted = false;
        discoveryStartMs = 0;
        chosenDeviceSsid[0] = '\0';
        homeSsid[0] = '\0';
        homePass[0] = '\0';
    }

private:
    static const uint8_t MAX_CANDIDATES = 5;

    PairingStep   step = PairingStep::IDLE;
    PairingResult lastResult = {};
    char homeSsid[33] = {0};
    char homePass[65] = {0};
    char chosenDeviceSsid[33] = {0};
    char candidates[MAX_CANDIDATES][33];
    uint8_t candidateCount = 0;
    bool provisionAttempted = false;
    uint32_t discoveryStartMs = 0;
    static const uint32_t DISCOVERY_TIMEOUT_MS = 60000;

    void pollScanning() {
        int n = WiFi.scanComplete();
        if (n == -2) { // WIFI_SCAN_FAILED
            step = PairingStep::FAILED;
            strncpy(lastResult.errorMsg, "Scan WiFi falhou", sizeof(lastResult.errorMsg) - 1);
            return;
        }
        if (n == -1) return; // ainda rodando, tenta de novo no próximo poll()

        candidateCount = 0;
        for (int i = 0; i < n && candidateCount < MAX_CANDIDATES; i++) {
            String ssid = WiFi.SSID(i);
            if (ssid.startsWith("SmartLife-") || ssid.startsWith("SL-") || ssid.startsWith("Tuya-")) {
                strncpy(candidates[candidateCount], ssid.c_str(), sizeof(candidates[candidateCount]) - 1);
                candidateCount++;
            }
        }
        WiFi.scanDelete();

        if (candidateCount == 0) {
            step = PairingStep::FAILED;
            strncpy(lastResult.errorMsg, "Nenhum device em modo pareamento encontrado", sizeof(lastResult.errorMsg) - 1);
            return;
        }

        // Publica a lista pro usuário escolher no site (ou auto-seleciona
        // se só achou um candidato).
        JsonDocument doc;
        doc["type"] = "pairing_candidates";
        JsonArray arr = doc["candidates"].to<JsonArray>();
        for (uint8_t i = 0; i < candidateCount; i++) arr.add(candidates[i]);
        mqttPublishDoc(TOPIC_PAIRING.c_str(), doc);

        if (candidateCount == 1) {
            selectDevice(candidates[0]);
        } else {
            step = PairingStep::WAITING_WIFI_CREDS; // aguarda select_device via MQTT
        }
    }

    void pollProvisioning() {
        if (provisionAttempted) return; // chamada única, ver nota abaixo
        provisionAttempted = true;

        Serial.printf("[PAIR][TUYA] Conectando no AP do device (%s) pra provisionar...\n", chosenDeviceSsid);

        // ATENÇÃO: ApModeProvisioning::provision() é bloqueante (até
        // connectTimeoutMs + tempo do POST) — mesma categoria de
        // limitação já documentada pra dispatchIotCommand(). Só é
        // seguro chamar aqui porque o pareamento é uma operação rara
        // e disparada manualmente, não parte do loop de controle normal.
        auto res = ApModeProvisioning::provision(chosenDeviceSsid, homeSsid, homePass);
        if (!res.success) {
            step = PairingStep::FAILED;
            strncpy(lastResult.errorMsg, res.message.c_str(), sizeof(lastResult.errorMsg) - 1);
            Serial.printf("[PAIR][TUYA] ❌ Provisionamento falhou: %s\n", res.message.c_str());
            return;
        }

        Serial.println("[PAIR][TUYA] ✅ Credenciais enviadas. Aguardando device aparecer na rede...");
        step = PairingStep::WAITING_CLOUD_ACTIVATION;
    }

    void pollFetchingKey() {
        if (discoveryStartMs == 0) discoveryStartMs = millis();

        if (millis() - discoveryStartMs > DISCOVERY_TIMEOUT_MS) {
            step = PairingStep::FAILED;
            strncpy(lastResult.errorMsg, "Timeout esperando device na rede apos provisionar", sizeof(lastResult.errorMsg) - 1);
            return;
        }

        TuyaDiscovery::poll([this](const TuyaDiscovery::TuyaBroadcastInfo& info) {
            if (this->step != PairingStep::FETCHING_LOCAL_KEY) return; // já resolvido/timeout
            if (!isKnownDevice(info.gwId.c_str())) {
                this->onNewDeviceSeen(info);
            }
        });
    }

    // TODO: trocar por lookup real na tabela de devices já pareados
    // (table.h / devices.h) — aqui é só um placeholder pra não repetir
    // o mesmo device no meio de um pareamento em andamento.
    bool isKnownDevice(const char* gwId) {
        (void)gwId;
        return false;
    }

    void onNewDeviceSeen(const TuyaDiscovery::TuyaBroadcastInfo& info) {
        Serial.printf("[PAIR][TUYA] 📡 Device visto na rede: gwId=%s ip=%s\n",
                     info.gwId.c_str(), info.ip.c_str());

        String localKey, ip;
        // Chamada bloqueante (HTTPS, ~1-2s) — igual dispatchIotCommand(),
        // aceitável aqui por ser um evento raro, não o loop de controle.
        if (!TuyaCloud::resolveLocalKey(tuyaCloudCreds, info.gwId, localKey, ip)) {
            // Pode falhar se o device não estiver cadastrado no seu
            // projeto Tuya ainda (precisa ter sido adicionado 1x via
            // app oficial — ver nota no header sobre bind/ativação).
            Serial.println("[PAIR][TUYA] ⚠️ Não achou local_key na Cloud API (device cadastrado no seu projeto?)");
            return; // continua tentando outros broadcasts até o timeout
        }

        // local_key da Tuya Cloud vem como string ASCII de 16 bytes
        // (ex: "&BL-jA9q:SKghyBG"), usada diretamente como chave AES —
        // NÃO é hex, é o próprio conteúdo em bytes.
        uint8_t localKeyBytes[16] = {0};
        size_t copyLen = min((size_t)16, localKey.length());
        memcpy(localKeyBytes, localKey.c_str(), copyLen);

        lastResult.ok = true;
        strncpy(lastResult.deviceId, info.gwId.c_str(), sizeof(lastResult.deviceId) - 1);
        strncpy(lastResult.ip, ip.length() ? ip.c_str() : info.ip.c_str(), sizeof(lastResult.ip) - 1);
        memcpy(lastResult.localKey, localKeyBytes, 16);
        lastResult.protocol = IotProtocol::TUYA_V35;

        // Registra na tabela e persiste — sem isso o pareamento "terminava"
        // sem o device nunca aparecer disponível pro dispatchIotCommand().
        // dpId default = 20 (switch_led, confirmado no mapping da sua lâmpada);
        // se algum dia você parear device de outra categoria, isso precisa
        // vir do usuário em vez de fixo aqui.
        registerIotDevice(lastResult.deviceId, lastResult.ip, localKeyBytes,
                           IotProtocol::TUYA_V35, /*dpId=*/20);
        saveIotDevicesToNVS();

        step = PairingStep::DONE;

        Serial.printf("[PAIR][TUYA] ✅ Pareamento concluido: %s @ %s\n", lastResult.deviceId, lastResult.ip);
    }
};

static TuyaPairingProvider tuyaPairing;

inline void pairingProviderPoll() {
    PairingStep s = tuyaPairing.currentStep();
    if (s != PairingStep::IDLE && s != PairingStep::DONE && s != PairingStep::FAILED) {
        tuyaPairing.poll();
    }
}

// Espera JSON em TOPIC_PAIRING, ex:
//   {"action":"start"}                                    (ou "start_pairing")
//   {"action":"select_device","ssid":"SmartLife-1234"}   (só se houver >1 candidato)
//   {"action":"wifi_creds","ssid":"...","pass":"..."}
//   {"action":"stop"}                                     (ou "stop_pairing"/"cancel")
inline void processPairing(const String& msg) {
    JsonDocument doc;
    if (deserializeJson(doc, msg)) {
        Serial.println("[PAIR] ❌ JSON inválido em processPairing()");
        return;
    }

    if (doc["type"].is<const char*>()) return;

    const char* action = doc["action"] | "";

    // Aceita os nomes que o dashboard manda hoje (start_pairing/stop_pairing)
    // como sinônimos dos nomes "canônicos" (start/stop) — evita depender de
    // sincronizar o front-end e o firmware toda vez que um dos dois muda.
    if (strcmp(action, "start") == 0 || strcmp(action, "start_pairing") == 0) {
        Serial.println("[PAIR] ▶️ Iniciando pareamento Tuya...");
        tuyaPairing.begin();
    }
    else if (strcmp(action, "stop") == 0 || strcmp(action, "stop_pairing") == 0 || strcmp(action, "cancel") == 0) {
        tuyaPairing.cancel();
    }
    else if (strcmp(action, "select_device") == 0) {
        const char* ssid = doc["ssid"] | "";
        if (strlen(ssid) == 0) { Serial.println("[PAIR] ❌ select_device sem ssid"); return; }
        tuyaPairing.selectDevice(ssid);
    }
    else if (strcmp(action, "wifi_creds") == 0) {
        const char* ssid = doc["ssid"] | "";
        const char* pass = doc["pass"] | "";
        if (strlen(ssid) == 0) {
            Serial.println("[PAIR] ❌ wifi_creds sem ssid");
            return;
        }
        if (tuyaPairing.currentStep() != PairingStep::WAITING_WIFI_CREDS) {
            Serial.println("[PAIR] ❌ Nenhum device selecionado ainda — clique 'Iniciar Pareamento' primeiro");
            return;
        }
        Serial.printf("[PAIR] 🔑 Credenciais recebidas para SSID: %s\n", ssid);
        tuyaPairing.submitWifiCredentials(ssid, pass);
    }
    else {
        Serial.printf("[PAIR] ⚠️ Ação desconhecida: %s\n", action);
    }
}
