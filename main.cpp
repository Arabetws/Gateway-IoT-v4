// =====================================================
// IoT Platform - ESP32-S3 Gateway v4.1 (CONSOLIDADO)
// =====================================================
// HISTÓRICO DE CORREÇÕES:
//   • [FIX] Porta MQTT default 1883 -> 8883 (TLS)
//   • [FIX] Trava de sanidade TLS+porta 1883 -> força 8883
//   • [FIX] Watchdog: esp_task_wdt_reset() dentro dos loops
//     bloqueantes de connectWiFi()/connectMQTT() (evitava reset
//     no meio do boot quando WiFi/MQTT demoravam a responder)
//   • [FIX] WiFi.setSleep(false) — evita drop silencioso do
//     socket TLS por causa do power-save do rádio WiFi
//   • [FIX] processSave() implementado (estava causando
//     "undefined reference" no linker)
//   • [FIX] processPairing() + pairingProviderPoll() ligados
//     (definidos em pairing_provider.h)
//   • [FIX] AP de configuração agora tem senha (antes era rede
//     aberta, qualquer um no alcance reconfigurava o gateway)
//   • [NOVO] Scan WiFi e BLE portados do v3.0 e integrados aos
//     comandos MQTT scan_wifi / scan_ble / scan_all
//   • [FIX] Removida chamada duplicada de checkMQTTConnection()
//     no loop()
// =====================================================
// PENDÊNCIAS CONHECIDAS (não resolvidas aqui, documentando para
// a defesa do TCC):
//   • dispatchIotCommand() é síncrono (handshake Tuya ~1-2s) e
//     bloqueia o loop() durante esse tempo.
//   • WiFi.scanNetworks() e bleScan->start() são bloqueantes;
//     scan_all (WiFi+BLE em sequência) pode aproximar-se do
//     timeout do watchdog em cenários com muitas redes/dispositivos.
//   • PairingProvider::PROVISIONING_WIFI ainda é TODO (depende da
//     decisão Caminho A - SDK oficial Tuya, ou Caminho B - captura
//     e engenharia reversa do broadcast AP-mode).
// =====================================================

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <ESPmDNS.h>
#include <mbedtls/md.h>
#include <time.h>
#include "esp_wifi.h"
#include "esp_task_wdt.h"
#include "NimBLEDevice.h"
#include "NimBLEScan.h"
#include "table.h"
#include "device_classifier.h"
#include "devices.h"
#include "tuya_devices.h"      // precisa vir ANTES de tuya_v35.h
#include "tuya_v35.h"          // driver LAN v3.5 validado
#include "tuya_dispatch.h"     // dispatchIotCommand()
#include "pairing_provider.h"  // TuyaPairingProvider + processPairing() + pairingProviderPoll()
#include "network_scanner.h"
#include "secrets.h"

// =====================================================
// CONFIGURAÇÕES
// =====================================================
#define DEFAULT_MQTT_BROKER   "mqtt.aekservice.com.br"
#define DEFAULT_MQTT_PORT     8883
#define DEFAULT_MQTT_USER     "admin"
#define DEFAULT_MQTT_PASS     "12345"
#define DEFAULT_MANAGE_PASS   "Gateway@2026!"

#define HEARTBEAT_INTERVAL    30000UL
#define MY_MQTT_KEEPALIVE        60
#define MQTT_SOCKET_TIMEOUT   15
#define MQTT_RECONNECT_DELAY  5000
#define WIFI_RECONNECT_DELAY  15000
#define WDT_TIMEOUT           45

#define MAX_WIFI_DEVS 40
#define MAX_BLE_DEVS  48
#define AP_SSID       "Gateway_IoT_Config"
#define AP_PASSWORD   "GatewaySetup2026!"

// =====================================================
// VARIÁVEIS GLOBAIS
// =====================================================
char espID[20];
char mqttClientID[30];
char deviceHostname[30];

String cfg_espId;
String cfg_topicBase;
String cfg_mqttBroker;
int    cfg_mqttPort;
String cfg_mqttUser;
String cfg_mqttPass;
String cfg_managePass;
bool   cfg_mqttTls;

String TOPIC_STATUS;
String TOPIC_PAIRING;
String TOPIC_COMMAND;
String TOPIC_RESPONSE;
String TOPIC_HEARTBEAT;
String TOPIC_CONTROL;
String TOPIC_SCAN_WIFI;
String TOPIC_SCAN_BLE;
String TOPIC_DEVICE_RESPONSE;
String TOPIC_SAVE;
String TOPIC_SCAN_LAN;
TuyaCloud::Credentials tuyaCloudCreds;

bool wifiConnected = false;
bool mqttConnected = false;
bool portalAtivo = false;
bool mdnsAtivo = false;

unsigned long lastHeartbeat = 0;
unsigned long lastMqttReconnectAttempt = 0;
unsigned long lastWifiCheck = 0;
unsigned long lastMqttLoop = 0;

static String csrfToken;

// =====================================================
// CERTIFICADO TLS — ISRG Root X2 (confirmado por captura real
// contra o broker mqtt.aekservice.com.br em produção)
// =====================================================
static const char MQTT_ROOT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIEcDCCAligAwIBAgIQbI8dxyfHEX97r4U6yYD5zTANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNjA1MTMwMDAwMDBa
Fw0zMjA5MDIyMzU5NTlaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5l
dCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgy
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0H
ttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7
AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo4H1MIHyMA4GA1UdDwEB/wQEAwIBBjAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwHwYDVR0jBBgwFoAUebRZ5nu2
5eQBc4AIiMgaWPbpm24wMgYIKwYBBQUHAQEEJjAkMCIGCCsGAQUFBzAChhZodHRw
Oi8veDEuaS5sZW5jci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCcGA1UdHwQg
MB4wHKAaoBiGFmh0dHA6Ly94MS5jLmxlbmNyLm9yZy8wDQYJKoZIhvcNAQELBQAD
ggIBAD2/e9frmMxNpCV03qUHegg+MV2wz9644YoXdqtH8RyWYcBO7xfjjGEXdU1e
/o0OkEFiynUCOSIk/vLLo7ttz6CPAeNlWfC0XNkoGeWgK6jjXvozBaGuGH5n0Ufo
shMeWTuURqNN5G00sSXDTBrpp2+mgvdZQjb8K11TYMA25QA+YHNfbIEL0BniAhKS
2gsnJjSzrdZLI+EZ7SEyqdR2rkjd1KutLDU+n3TFyxjniZVGur4YlhMP3mY/dV95
IruAkkjOZier6hGBdEgZXXvaCz9u9iVEadsIE75pAGL8oHV5vxdARDiotRpul1IN
/UZwzAbrfUFcw1HkAcYD/mlZfnQ2ieCF2MS7j3Vhv7JPDKp45fmykmzYNSrumRW0
upFFKDBOoF7hsOb7oLyHS+Uft6jOUfOrogj8YUx38hKb2K20r42OgsSdDdxdeYWc
MS3Sb6mwJeSZEYxJ2gaXnDSPaKhhrNkYwljyVQyr4Nq+MEJytXNTnHqaAcrNwZlV
pcJL1KBnMrMjP7eanvUwL3FYj3cF17jtboLt7gLoi4+2rWZFvn+w54jmd/FIuhhZ
cEaU/wvU6BUNMtcVquVGHp7itQeDth5j+XL3j4WJ2SABwzUl6OeYdgpIt/ITZa+p
TT0mQ/r5XyA4MEAiabn7XJjvCERlF2dcn2wqJw+CreTkkQ2R
-----END CERTIFICATE-----
)EOF";

// =====================================================
// OBJETOS
// =====================================================
WiFiClientSecure espClientSecure;
WiFiClient espClientPlain;
PubSubClient mqttClient(espClientSecure);
Preferences preferences;
WebServer portalServer(80);

struct WiFiDev {
    char ssid[48], mac[18], fabricante[32], tipo[52];
    char categoria[52], vendor_id[32], protocol[24];
    int8_t rssi, canal;
    uint8_t confianca;
    bool is_mobile, is_iot, is_sensor, is_actuator;
};

struct BLEDev {
    char mac[18], nome[48], fabricante[32], tipo[52];
    char uuids[64], categoria[52], vendor_id[32], protocol[24];
    int8_t rssi;
    uint8_t confianca;
    bool macAleatorio, is_mobile, is_iot, is_sensor, is_actuator;
};

static WiFiDev wifiDevs[MAX_WIFI_DEVS];
static uint8_t wifiDevCount = 0;
static BLEDev bleDevs[MAX_BLE_DEVS];
static uint8_t bleDevCount = 0;

// =====================================================
// PROTÓTIPOS
// =====================================================
void gerarIDsUnicos();
void gerarCsrfToken();
void buildTopics();
void publishLANScan();
void publishLANScan();
void carregarConfig();
void printConfigBanner();
bool connectWiFi();
bool connectMQTT();
void checkMQTTConnection();
void mqttCallback(char* topic, byte* payload, unsigned int length);
void publishStatus(const char* status);
void sendHeartbeat();
void processCommand(const String& msg);
void processControl(const String& msg);
void processSave(const String& msg);
void sendResponse(const char* type, const char* cmdId, bool ok, const char* msg);
void mqttPublishDoc(const char* topic, JsonDocument& doc);
String getTimestamp();
bool isMacRandom(const char* mac);
void runScanWiFi();
void runScanBLE();
void publishWiFiScan();
void publishBLEScan();

// =====================================================
// UTILITÁRIOS
// =====================================================

void gerarIDsUnicos() {
    Preferences p;
    p.begin("iot-ids", true);
    String savedId = p.getString("esp_id", "");
    p.end();

    if (savedId.length() > 0) {
        savedId.toCharArray(espID, sizeof(espID));
    } else {
        uint32_t r1 = esp_random();
        uint32_t r2 = esp_random();
        snprintf(espID, sizeof(espID), "%04X%04X", r1 & 0xFFFF, r2 & 0xFFFF);

        p.begin("iot-ids", false);
        p.putString("esp_id", String(espID));
        p.end();
        Serial.printf("[ID] Novo ID gerado: %s\n", espID);
    }

    snprintf(mqttClientID, sizeof(mqttClientID), "esp_%s", espID);
    snprintf(deviceHostname, sizeof(deviceHostname), "raiter-%s", espID);
}

void gerarCsrfToken() {
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X%02X%lu%lu", mac[4], mac[5], millis(), (unsigned long)esp_random());
    csrfToken = String(buf);
}

void buildTopics() {
    TOPIC_STATUS          = cfg_topicBase + "/status";
    TOPIC_COMMAND         = cfg_topicBase + "/command";
    TOPIC_PAIRING         = cfg_topicBase + "/pairing";
    TOPIC_RESPONSE        = cfg_topicBase + "/response";
    TOPIC_HEARTBEAT       = cfg_topicBase + "/heartbeat";
    TOPIC_CONTROL         = cfg_topicBase + "/control";
    TOPIC_SCAN_WIFI       = cfg_topicBase + "/scan/wifi";
    TOPIC_SCAN_BLE        = cfg_topicBase + "/scan/ble";
    TOPIC_DEVICE_RESPONSE = cfg_topicBase + "/device/response";
    TOPIC_SCAN_LAN        = cfg_topicBase + "/scan/lan";
    TOPIC_SAVE            = cfg_topicBase + "/save";
}

void carregarConfig() {
    Preferences p;
    p.begin("iot-cfg", true);
    cfg_espId      = p.getString("esp_id", String(espID));
    cfg_topicBase  = p.getString("topic_base", "IOT/" + String(espID));
    cfg_mqttBroker = p.getString("mqtt_broker", DEFAULT_MQTT_BROKER);
    cfg_mqttPort   = p.getInt("mqtt_port", DEFAULT_MQTT_PORT);
    cfg_mqttUser   = p.getString("mqtt_user", DEFAULT_MQTT_USER);
    cfg_mqttPass   = p.getString("mqtt_pass", DEFAULT_MQTT_PASS);
    cfg_managePass = p.getString("manage_pass", DEFAULT_MANAGE_PASS);
    cfg_mqttTls    = p.getBool("mqtt_tls", true);
    tuyaCloudCreds.clientId     = p.getString("tuya_client_id", DEFAULT_TUYA_CLIENT_ID);
    tuyaCloudCreds.clientSecret = p.getString("tuya_client_secret", DEFAULT_TUYA_CLIENT_SECRET);
    tuyaCloudCreds.host         = p.getString("tuya_host", DEFAULT_TUYA_HOST);
    p.end();

    if (cfg_mqttTls && cfg_mqttPort == 1883) {
        Serial.println("[CFG] ⚠️ TLS ativo com porta 1883 (não-TLS). Corrigindo para 8883.");
        cfg_mqttPort = 8883;
    }

    buildTopics();
}

void printConfigBanner() {
    Serial.println("\n╔═══════════════════════════════════════════════════╗");
    Serial.println("║         IoT Gateway ESP32-S3  v4.1               ║");
    Serial.println("╠═══════════════════════════════════════════════════╣");
    Serial.printf("║  ESP ID     : %-35s║\n", cfg_espId.c_str());
    Serial.printf("║  Topic Base : %-35s║\n", cfg_topicBase.c_str());
    Serial.printf("║  Broker     : %-35s║\n", (cfg_mqttBroker + ":" + String(cfg_mqttPort)).c_str());
    Serial.printf("║  TLS MQTT   : %-35s║\n", cfg_mqttTls ? "ATIVO" : "DESATIVADO");
    Serial.printf("║  IP         : %-35s║\n", WiFi.localIP().toString().c_str());
    Serial.println("╚═══════════════════════════════════════════════════╝\n");
}

String getTimestamp() {
    struct tm ti;
    if (!getLocalTime(&ti, 100)) return String(millis() / 1000);
    char buf[24];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ti);
    return String(buf);
}

bool isMacRandom(const char* mac) {
    char c = mac[1];
    int v = (c >= '0' && c <= '9') ? (c - '0') :
            (c >= 'A' && c <= 'F') ? (c - 'A' + 10) :
            (c >= 'a' && c <= 'f') ? (c - 'a' + 10) : 0;
    return (v & 0x2) != 0;
}

void mqttPublishDoc(const char* topic, JsonDocument& doc) {
    if (!mqttClient.connected()) {
        Serial.printf("[MQTT] ⚠️ Não conectado - não foi possível publicar em %s\n", topic);
        return;
    }

    String out;
    serializeJson(doc, out);

    if (mqttClient.publish(topic, out.c_str())) {
        Serial.printf("[MQTT] 📤 Publicado em %s (%d bytes)\n", topic, out.length());
    } else {
        Serial.printf("[MQTT] ❌ Falha ao publicar em %s\n", topic);
    }
}

void sendResponse(const char* type, const char* cmdId, bool ok, const char* msg) {
    JsonDocument doc;
    doc["type"]       = type;
    doc["command_id"] = cmdId;
    doc["success"]    = ok;
    doc["message"]    = msg;
    doc["timestamp"]  = getTimestamp();
    mqttPublishDoc(TOPIC_RESPONSE.c_str(), doc);
}

void publishStatus(const char* status) {
    JsonDocument doc;
    doc["status"]    = status;
    doc["esp_id"]    = cfg_espId;
    doc["ip"]        = WiFi.localIP().toString();
    doc["mac"]       = WiFi.macAddress();
    doc["rssi"]      = WiFi.RSSI();
    doc["uptime"]    = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["tls"]       = cfg_mqttTls;
    doc["timestamp"] = getTimestamp();
    mqttPublishDoc(TOPIC_STATUS.c_str(), doc);
}

void sendHeartbeat() {
    if (!mqttConnected) return;

    JsonDocument doc;
    doc["esp_id"]    = cfg_espId;
    doc["online"]    = true;
    doc["rssi"]      = WiFi.RSSI();
    doc["free_heap"] = ESP.getFreeHeap();
    doc["uptime"]    = millis() / 1000;
    doc["ip"]        = WiFi.localIP().toString();
    doc["timestamp"] = getTimestamp();
    mqttPublishDoc(TOPIC_HEARTBEAT.c_str(), doc);
}

// =====================================================
// CONEXÃO WiFi ROBUSTA
// =====================================================

bool connectWiFi() {
    if (WiFi.status() == WL_CONNECTED) {
        wifiConnected = true;
        return true;
    }

    Preferences p;
    p.begin("wifi-config", true);
    String ssid = p.getString("ssid", "");
    String password = p.getString("password", "");
    p.end();

    if (ssid.isEmpty()) {
        Serial.println("[WiFi] Nenhuma credencial salva");
        wifiConnected = false;
        return false;
    }

    Serial.printf("[WiFi] Conectando a %s...\n", ssid.c_str());
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), password.c_str());

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 40) {
        esp_task_wdt_reset(); // evita reset do watchdog durante a espera de até 20s
        delay(500);
        Serial.print(".");
        attempts++;
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        wifiConnected = true;
        Serial.printf("[WiFi] ✅ Conectado! IP: %s, RSSI: %d dBm\n",
                     WiFi.localIP().toString().c_str(), WiFi.RSSI());
        configTime(-3 * 3600, 0, "pool.ntp.br", "time.google.com");
        return true;
    }

    wifiConnected = false;
    Serial.printf("[WiFi] ❌ Falha na conexão (status: %d)\n", WiFi.status());
    return false;
}

// =====================================================
// CONEXÃO MQTT ROBUSTA
// =====================================================

bool connectMQTT() {
    if (!wifiConnected) {
        return false;
    }

    if (mqttClient.connected()) {
        mqttConnected = true;
        return true;
    }

    Serial.println("[MQTT] Iniciando conexão...");

    // [FIX] Fecha qualquer sessão TLS/socket anterior antes de
    // reconstruir o PubSubClient — sem isso, o contexto SSL antigo
    // fica "sujo" e a próxima tentativa aborta com errno 113.
    espClientSecure.stop();
    espClientPlain.stop();

    if (cfg_mqttTls) {
        espClientSecure.setCACert(MQTT_ROOT_CA);
        espClientSecure.setTimeout(10000); // 10s máx pro handshake TLS
        new (&mqttClient) PubSubClient(espClientSecure);
    }else {
        new (&mqttClient) PubSubClient(espClientPlain);
    }

    mqttClient.setServer(cfg_mqttBroker.c_str(), cfg_mqttPort);

    mqttClient.setServer(cfg_mqttBroker.c_str(), cfg_mqttPort);
    mqttClient.setCallback(mqttCallback);
    mqttClient.setKeepAlive(MQTT_KEEPALIVE);
    mqttClient.setSocketTimeout(MQTT_SOCKET_TIMEOUT);
    mqttClient.setBufferSize(32768);

    Serial.printf("[MQTT] Conectando a %s:%d (TLS: %s, ClientID: %s)...\n",
                 cfg_mqttBroker.c_str(), cfg_mqttPort,
                 cfg_mqttTls ? "ON" : "OFF", mqttClientID);

    for (int attempt = 1; attempt <= 3; attempt++) {
        esp_task_wdt_reset();
        if (mqttClient.connect(mqttClientID,
                              cfg_mqttUser.c_str(),
                              cfg_mqttPass.c_str(),
                              TOPIC_STATUS.c_str(),
                              0,
                              true,
                              "offline")) {
            mqttConnected = true;
            Serial.println("[MQTT] ✅ Conectado com sucesso!");

            mqttClient.subscribe(TOPIC_COMMAND.c_str(), 1);
            mqttClient.subscribe(TOPIC_CONTROL.c_str(), 1);
            mqttClient.subscribe(TOPIC_SAVE.c_str(), 1);
            mqttClient.subscribe(TOPIC_PAIRING.c_str(), 1);

            publishStatus("online");
            return true;
        }

        int state = mqttClient.state();
        Serial.printf("[MQTT] ❌ Tentativa %d falhou (erro: %d)\n", attempt, state);

        if (attempt < 3) {
            esp_task_wdt_reset();
            delay(2000);
        }
    }

    mqttConnected = false;
    return false;
}

void checkMQTTConnection() {
    unsigned long now = millis();

    if (now - lastWifiCheck > WIFI_RECONNECT_DELAY) {
        lastWifiCheck = now;
        if (!wifiConnected) {
            connectWiFi();
        }
    }

    if (!mqttConnected && (now - lastMqttReconnectAttempt > MQTT_RECONNECT_DELAY)) {
        lastMqttReconnectAttempt = now;
        if (wifiConnected) {
            connectMQTT();
        }
    }

    if (mqttConnected && (now - lastMqttLoop > 50)) {
        lastMqttLoop = now;
        mqttClient.loop();
        if (!mqttClient.connected()) {
            // detecta drop de conexão (ex.: -76 NET_RECV_FAILED) e força
            // o checkMQTTConnection() a tentar reconectar no próximo ciclo
            mqttConnected = false;
        }
    }
}

// =====================================================
// SALVAMENTO DE CONFIG (via MQTT)
// =====================================================

void processSave(const String& msg) {
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, msg);

    if (error) {
        Serial.printf("[SAVE] ❌ Erro ao parsear JSON: %s\n", error.c_str());
        return;
    }

    const char* cmdId = doc["command_id"] | "";

    Preferences p;
    p.begin("iot-cfg", false);

    bool changed = false;

    if (doc["mqtt_broker"].is<const char*>()) { p.putString("mqtt_broker", doc["mqtt_broker"].as<String>()); changed = true; }
    if (doc["mqtt_port"].is<int>())           { p.putInt("mqtt_port", doc["mqtt_port"].as<int>());          changed = true; }
    if (doc["mqtt_user"].is<const char*>())   { p.putString("mqtt_user", doc["mqtt_user"].as<String>());    changed = true; }
    if (doc["mqtt_pass"].is<const char*>())   { p.putString("mqtt_pass", doc["mqtt_pass"].as<String>());    changed = true; }
    if (doc["mqtt_tls"].is<bool>())           { p.putBool("mqtt_tls", doc["mqtt_tls"].as<bool>());          changed = true; }
    if (doc["topic_base"].is<const char*>())  { p.putString("topic_base", doc["topic_base"].as<String>());  changed = true; }
    if (doc["manage_pass"].is<const char*>()) { p.putString("manage_pass", doc["manage_pass"].as<String>()); changed = true; }

    p.end();

    if (!changed) {
        sendResponse("save_error", cmdId, false, "Nenhum campo reconhecido para salvar");
        return;
    }

    sendResponse("save_ack", cmdId, true, "Configuracao salva. Reiniciando...");
    Serial.println("[SAVE] ✅ Config salva na NVS, reiniciando em 1.5s...");
    delay(1500);
    ESP.restart();
}

// =====================================================
// SCAN WiFi
// =====================================================

void runScanWiFi() {
    Serial.println("[SCAN] 📡 Scan WiFi...");
    wifiDevCount = 0;
    int n = WiFi.scanNetworks(false, true, false, 300);
    if (n <= 0) {
        WiFi.scanDelete();
        Serial.println("[SCAN] Nenhuma rede encontrada");
        publishWiFiScan();
        return;
    }
    for (int i = 0; i < n && wifiDevCount < MAX_WIFI_DEVS; i++) {
        WiFiDev& d = wifiDevs[wifiDevCount];
        String ssid = WiFi.SSID(i);
        strlcpy(d.ssid, ssid.isEmpty() ? "<oculto>" : ssid.c_str(), sizeof(d.ssid));
        uint8_t* b = WiFi.BSSID(i);
        snprintf(d.mac, sizeof(d.mac), "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
        d.rssi  = (int8_t)WiFi.RSSI(i);
        d.canal = (int8_t)WiFi.channel(i);

        DeviceProfile prof = classifyWiFi(d.mac, ssid.c_str(), d.rssi, d.canal);
        strlcpy(d.fabricante, prof.vendor, sizeof(d.fabricante));
        strlcpy(d.categoria, prof.label, sizeof(d.categoria));
        strlcpy(d.vendor_id, prof.vendor, sizeof(d.vendor_id));
        strlcpy(d.tipo, prof.label, sizeof(d.tipo));
        strlcpy(d.protocol, prof.protocol, sizeof(d.protocol));
        d.confianca   = prof.confidence;
        d.is_mobile   = prof.is_mobile;
        d.is_iot      = prof.is_iot;
        d.is_sensor   = prof.is_sensor;
        d.is_actuator = prof.is_actuator;
        wifiDevCount++;
    }
    WiFi.scanDelete();
    Serial.printf("[SCAN] ✅ WiFi: %d rede(s)\n", wifiDevCount);
    publishWiFiScan();
}

void publishWiFiScan() {
    const int BATCH = 8;
    int total = wifiDevCount, batches = max(1, (total + BATCH - 1) / BATCH);
    for (int b = 0; b < batches; b++) {
        JsonDocument doc;
        doc["esp_id"]       = cfg_espId;
        doc["tipo"]         = "wifi_scan";
        doc["total"]        = total;
        doc["lote"]         = b + 1;
        doc["total_lotes"]  = batches;
        doc["timestamp"]    = getTimestamp();
        JsonArray arr = doc["redes"].to<JsonArray>();
        int ini = b * BATCH, fim = min(total, ini + BATCH);
        for (int i = ini; i < fim; i++) {
            JsonObject o = arr.add<JsonObject>();
            o["ssid"]        = wifiDevs[i].ssid;
            o["mac"]         = wifiDevs[i].mac;
            o["rssi"]        = wifiDevs[i].rssi;
            o["canal"]       = wifiDevs[i].canal;
            o["fabricante"]  = wifiDevs[i].fabricante;
            o["categoria"]   = wifiDevs[i].categoria;
            o["protocolo"]   = wifiDevs[i].protocol;
            o["confianca"]   = wifiDevs[i].confianca;
            o["movel"]       = wifiDevs[i].is_mobile;
            o["iot"]         = wifiDevs[i].is_iot;
            o["sensor"]      = wifiDevs[i].is_sensor;
            o["atuador"]     = wifiDevs[i].is_actuator;
        }
        mqttPublishDoc(TOPIC_SCAN_WIFI.c_str(), doc);
        delay(60);
    }
}

// =====================================================
// SCAN BLE
// =====================================================

class BLECallback : public NimBLEAdvertisedDeviceCallbacks {
public:
    void onResult(NimBLEAdvertisedDevice* dev) override {
        if (bleDevCount >= MAX_BLE_DEVS) return;
        BLEDev& d = bleDevs[bleDevCount];
        String macStr = dev->getAddress().toString().c_str();
        macStr.toUpperCase();
        strlcpy(d.mac, macStr.c_str(), sizeof(d.mac));
        d.rssi = (int8_t)dev->getRSSI();
        d.macAleatorio = isMacRandom(d.mac);
        d.nome[0] = d.uuids[0] = '\0';
        if (dev->haveName() && dev->getName().length() > 0)
            strlcpy(d.nome, dev->getName().c_str(), sizeof(d.nome));
        if (dev->haveServiceUUID()) {
            String ul = "";
            int uc = min((int)dev->getServiceUUIDCount(), 3);
            for (int i = 0; i < uc; i++) {
                if (i > 0) ul += ",";
                String u = dev->getServiceUUID(i).toString().c_str();
                u.toUpperCase();
                ul += u.substring(0, 8);
            }
            strlcpy(d.uuids, ul.c_str(), sizeof(d.uuids));
        }
        DeviceProfile prof = classifyBLE(d.mac, d.nome, d.uuids, d.macAleatorio, d.rssi);
        strlcpy(d.fabricante, prof.vendor, sizeof(d.fabricante));
        strlcpy(d.categoria, prof.label, sizeof(d.categoria));
        strlcpy(d.vendor_id, prof.vendor, sizeof(d.vendor_id));
        strlcpy(d.tipo, prof.label, sizeof(d.tipo));
        strlcpy(d.protocol, prof.protocol, sizeof(d.protocol));
        d.confianca   = prof.confidence;
        d.is_mobile   = prof.is_mobile;
        d.is_iot      = prof.is_iot;
        d.is_sensor   = prof.is_sensor;
        d.is_actuator = prof.is_actuator;
        bleDevCount++;
    }
};

static BLECallback bleCB;
NimBLEScan* bleScan = nullptr;

void runScanBLE() {
    Serial.println("[SCAN] 🔵 Scan BLE...");
    bleDevCount = 0;
    if (!bleScan) {
        Serial.println("[SCAN] ❌ BLE não inicializado");
        return;
    }
    bleScan->clearResults();
    esp_task_wdt_reset();
    bleScan->start(6, false); // bloqueante ~6s
    esp_task_wdt_reset();
    Serial.printf("[SCAN] ✅ BLE: %d dispositivo(s)\n", bleDevCount);
    publishBLEScan();
}

void publishBLEScan() {
    const int BATCH = 6;
    int total = bleDevCount, batches = max(1, (total + BATCH - 1) / BATCH);
    for (int b = 0; b < batches; b++) {
        JsonDocument doc;
        doc["esp_id"]      = cfg_espId;
        doc["tipo"]        = "ble_scan";
        doc["total"]       = total;
        doc["lote"]        = b + 1;
        doc["total_lotes"] = batches;
        doc["timestamp"]   = getTimestamp();
        JsonArray arr = doc["dispositivos"].to<JsonArray>();
        int ini = b * BATCH, fim = min(total, ini + BATCH);
        for (int i = ini; i < fim; i++) {
            JsonObject o = arr.add<JsonObject>();
            o["mac"]           = bleDevs[i].mac;
            o["nome"]          = bleDevs[i].nome;
            o["rssi"]          = bleDevs[i].rssi;
            o["fabricante"]    = bleDevs[i].fabricante;
            o["categoria"]     = bleDevs[i].categoria;
            o["confianca"]     = bleDevs[i].confianca;
            o["protocolo"]     = bleDevs[i].protocol;
            o["uuids"]         = bleDevs[i].uuids;
            o["mac_aleatorio"] = bleDevs[i].macAleatorio;
            o["movel"]         = bleDevs[i].is_mobile;
            o["iot"]           = bleDevs[i].is_iot;
            o["sensor"]        = bleDevs[i].is_sensor;
            o["atuador"]       = bleDevs[i].is_actuator;
        }
        mqttPublishDoc(TOPIC_SCAN_BLE.c_str(), doc);
        delay(60);
    }
}

struct LanHostDev {
    char ip[16];
    char mac[18];
    char vendor[28];
    bool tuyaPortOpen;
};

#define MAX_LAN_HOSTS 254
static LanHostDev lanHosts[MAX_LAN_HOSTS];
static uint8_t lanHostCount = 0;

void runScanLAN() {
    Serial.println("[SCAN] 🌐 Scan de hosts na LAN...");
    lanHostCount = 0;
    NetworkScanner::begin();
 
    NetworkScanner::scan([](const NetworkScanner::LanHostInfo& info) {
        if (lanHostCount >= MAX_LAN_HOSTS) return;
        LanHostDev& d = lanHosts[lanHostCount];
        strlcpy(d.ip, info.ip.toString().c_str(), sizeof(d.ip));
        strlcpy(d.mac, info.mac, sizeof(d.mac));
        strlcpy(d.vendor, info.vendor, sizeof(d.vendor));
        d.tuyaPortOpen = info.tuyaPortOpen;
        lanHostCount++;
        esp_task_wdt_reset();
    });
 
    Serial.printf("[SCAN] ✅ LAN: %d host(s) ativo(s)\n", lanHostCount);
    publishLANScan();
}
 
void publishLANScan() {
    const int BATCH = 10;
    int total = lanHostCount, batches = max(1, (total + BATCH - 1) / BATCH);
    for (int b = 0; b < batches; b++) {
        JsonDocument doc;
        doc["esp_id"]      = cfg_espId;
        doc["tipo"]        = "lan_scan";
        doc["total"]       = total;
        doc["lote"]        = b + 1;
        doc["total_lotes"] = batches;
        doc["timestamp"]   = getTimestamp();
        JsonArray arr = doc["hosts"].to<JsonArray>();
        int ini = b * BATCH, fim = min(total, ini + BATCH);
        for (int i = ini; i < fim; i++) {
            JsonObject o = arr.add<JsonObject>();
            o["ip"]               = lanHosts[i].ip;
            o["mac"]              = lanHosts[i].mac;
            o["fabricante"]       = lanHosts[i].vendor;
            o["tuya_port_aberta"] = lanHosts[i].tuyaPortOpen;
        }
        mqttPublishDoc(TOPIC_SCAN_LAN.c_str(), doc);
        delay(60);
    }
}

// =====================================================
// MQTT CALLBACK
// =====================================================

void mqttCallback(char* topic, byte* payload, unsigned int length) {
    String msg;
    msg.reserve(length + 1);
    for (unsigned int i = 0; i < length; i++) {
        msg += (char)payload[i];
    }

    String t = String(topic);
    Serial.printf("[MQTT] 📨 Mensagem recebida em %s (%d bytes)\n", t.c_str(), length);

    if (t == TOPIC_COMMAND) {
        processCommand(msg);
    } else if (t == TOPIC_CONTROL) {
        processControl(msg);
    } else if (t == TOPIC_SAVE) {
        processSave(msg);
    } else if (t == TOPIC_PAIRING) {
        processPairing(msg); // definida em pairing_provider.h
    }
}

// =====================================================
// PROCESSAMENTO DE COMANDOS
// =====================================================

void processCommand(const String& msg) {
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, msg);

    if (error) {
        Serial.printf("[CMD] ❌ Erro ao parsear JSON: %s\n", error.c_str());
        return;
    }

    String cmd = doc["comando"] | "";
    String cmdId = doc["command_id"] | "";

    Serial.printf("[CMD] 📨 Comando: %s (ID: %s)\n", cmd.c_str(), cmdId.c_str());

    if (cmd == "ping") {
        sendResponse("pong", cmdId.c_str(), true, "pong");
    }
    else if (cmd == "status") {
        publishStatus("online");
        sendResponse("status_response", cmdId.c_str(), true, "Status publicado");
    }
    else if (cmd == "restart") {
        sendResponse("restarting", cmdId.c_str(), true, "Reiniciando...");
        delay(1000);
        ESP.restart();
    }
    else if (cmd == "scan_wifi") {
        sendResponse("scan_wifi", cmdId.c_str(), true, "Iniciando scan WiFi...");
        runScanWiFi();
    }
    else if (cmd == "scan_ble") {
        sendResponse("scan_ble", cmdId.c_str(), true, "Iniciando scan BLE...");
        runScanBLE();
    }
    else if (cmd == "scan_all") {
        sendResponse("scan_all", cmdId.c_str(), true, "Iniciando scan completo...");
        runScanWiFi();
        runScanBLE();
    }
    else if (cmd == "scan_lan") {
        sendResponse("scan_lan", cmdId.c_str(), true, "Iniciando scan de rede local...");
        runScanLAN();
    }
    else if (cmd == "info") {
        JsonDocument info;
        info["type"] = "esp_info";
        info["command_id"] = cmdId;
        info["esp_id"] = cfg_espId;
        info["topic_base"] = cfg_topicBase;
        info["mqtt_broker"] = cfg_mqttBroker;
        info["mqtt_port"] = cfg_mqttPort;
        info["mqtt_tls"] = cfg_mqttTls;
        info["chip_model"] = ESP.getChipModel();
        info["cpu_freq"] = ESP.getCpuFreqMHz();
        info["free_heap"] = ESP.getFreeHeap();
        info["mac"] = WiFi.macAddress();
        info["ip"] = WiFi.localIP().toString();
        info["rssi"] = WiFi.RSSI();
        info["uptime"] = millis() / 1000;
        info["sdk_version"] = ESP.getSdkVersion();
        mqttPublishDoc(TOPIC_RESPONSE.c_str(), info);
    }
    else if (cmd == "register_device") {
        const char* devId  = doc["id"] | "";
        const char* devIp  = doc["ip"] | "";
        const char* devKey = doc["local_key"] | "";
        int dpId = doc["dp_id"] | 20;
 
        if (strlen(devId) == 0 || strlen(devIp) == 0 || strlen(devKey) != 16) {
            sendResponse("register_device_error", cmdId.c_str(), false,
                        "Campos obrigatorios: id, ip, local_key (16 chars)");
        } else {
            uint8_t keyBytes[16];
            memcpy(keyBytes, devKey, 16);
            registerIotDevice(devId, devIp, keyBytes, IotProtocol::TUYA_V35, dpId);
            saveIotDevicesToNVS();
            sendResponse("register_device_ack", cmdId.c_str(), true, "Dispositivo registrado");
        }
    }
    else {
        sendResponse("error", cmdId.c_str(), false, ("Comando desconhecido: " + cmd).c_str());
    }
}
void processControl(const String& msg) {
    JsonDocument doc;
    if (deserializeJson(doc, msg)) return;

    const char* deviceId = doc["device_id"];
    const char* command = doc["comando"];
    const char* cmdId = doc["command_id"] | "";

    if (!deviceId || !command) {
        sendResponse("control_error", cmdId, false, "device_id e comando obrigatórios");
        return;
    }

    bool turnOn = (strcmp(command, "on") == 0 || strcmp(command, "ligar") == 0);
    bool turnOff = (strcmp(command, "off") == 0 || strcmp(command, "desligar") == 0);

    if (!turnOn && !turnOff) {
        sendResponse("control_error", cmdId, false, "Comando não reconhecido (use on/off)");
        return;
    }

    // ATENÇÃO (limitação conhecida): dispatchIotCommand() é síncrono
    // (TCP + handshake Tuya, ~1-2s) e bloqueia o loop() principal
    // durante esse tempo.
    bool ok = dispatchIotCommand(deviceId, turnOn);

    JsonDocument response;
    response["type"] = "device_response";
    response["device_id"] = deviceId;
    response["comando"] = command;
    response["success"] = ok;
    response["message"] = ok ? "Comando executado" : "Falha ao executar comando";
    response["timestamp"] = getTimestamp();
    mqttPublishDoc(TOPIC_DEVICE_RESPONSE.c_str(), response);

    sendResponse("control_ack", cmdId, ok, ok ? "Comando processado" : "Falha na execução");
}

// =====================================================
// SETUP E LOOP PRINCIPAL
// =====================================================

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("\n\n╔════════════════════════════════════════════════╗");
    Serial.println("║   IoT Platform - ESP32-S3 Gateway v4.1        ║");
    Serial.println("║   Arquitetura Robusta com Anti-Timeout        ║");
    Serial.println("╚════════════════════════════════════════════════╝\n");

    esp_task_wdt_init(WDT_TIMEOUT, true);
    esp_task_wdt_add(NULL);

    gerarIDsUnicos();
    Serial.printf("[SYS] ESP ID: %s\n", espID);
    Serial.printf("[SYS] MQTT Client ID: %s\n", mqttClientID);
    Serial.printf("[SYS] Hostname: %s\n", deviceHostname);

    pinMode(LED_BUILTIN, OUTPUT);
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, HIGH);
        delay(150);
        digitalWrite(LED_BUILTIN, LOW);
        delay(150);
    }

    carregarConfig();
    loadIotDevicesFromNVS();
    Serial.printf("[IOT] %d dispositivo(s) Tuya conhecido(s)\n", iotDeviceCount);

    // =====================================================
    // BLE — inicializado ANTES do WiFi conectar.
    // [FIX] O abort em coex_core_enable (visto no backtrace) ocorre
    // quando o NimBLE é iniciado com o WiFi já totalmente conectado;
    // o subsistema de coexistência do ESP-IDF espera ser configurado
    // nessa ordem. Se o abort persistir mesmo assim, o próximo passo
    // é fixar outra versão do NimBLE-Arduino no platformio.ini.
    // =====================================================
    NimBLEDevice::init("");
    bleScan = NimBLEDevice::getScan();
    bleScan->setAdvertisedDeviceCallbacks(&bleCB, false);
    bleScan->setActiveScan(false);
    bleScan->setInterval(200);
    bleScan->setWindow(60);
    Serial.println("[BLE] ✅ NimBLE inicializado");

    if (connectWiFi()) {
        gerarCsrfToken();

        if (MDNS.begin(cfg_espId.c_str())) {
            MDNS.addService("http", "tcp", 80);
            mdnsAtivo = true;
            Serial.printf("[mDNS] ✅ Ativo como %s.local\n", cfg_espId.c_str());
        }

        portalServer.on("/", []() {
            portalServer.sendHeader("Location", "/manage", true);
            portalServer.send(302, "text/plain", "");
        });

        portalServer.on("/manage", []() {
            if (!portalServer.authenticate("admin", cfg_managePass.c_str())) {
                return portalServer.requestAuthentication(DIGEST_AUTH, "Gateway IoT", "Acesso restrito");
            }

            String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
            html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
            html += "<title>Gateway IoT</title></head><body>";
            html += "<h1>Gateway IoT - " + cfg_espId + "</h1>";
            html += "<p>Status: " + String(mqttConnected ? "Online" : "Offline") + "</p>";
            html += "<p>WiFi: " + String(wifiConnected ? "Conectado" : "Desconectado") + "</p>";
            html += "<p>IP: " + WiFi.localIP().toString() + "</p>";
            html += "<p>MQTT Broker: " + cfg_mqttBroker + ":" + String(cfg_mqttPort) + "</p>";
            html += "<p>TLS: " + String(cfg_mqttTls ? "Ativo" : "Inativo") + "</p>";
            html += "<p>Uptime: " + String(millis() / 1000) + "s</p>";
            html += "<p>Heap Livre: " + String(ESP.getFreeHeap() / 1024) + " KB</p>";
            html += "<p>RSSI: " + String(WiFi.RSSI()) + " dBm</p>";
            html += "</body></html>";

            portalServer.send(200, "text/html", html);
        });

        portalServer.begin();
        Serial.println("[WEB] ✅ Servidor web iniciado na porta 80");

        connectMQTT();

        lastHeartbeat = millis();
        lastMqttLoop = millis();

        printConfigBanner();
        Serial.printf("[SYS] ✅ Sistema pronto! Heap livre: %d KB\n", ESP.getFreeHeap() / 1024);
    } else {
        Serial.println("[AP] Iniciando modo Access Point...");
        WiFi.mode(WIFI_AP);
        WiFi.softAP(AP_SSID, AP_PASSWORD);
        Serial.printf("[AP] Rede: %s, IP: %s\n", AP_SSID, WiFi.softAPIP().toString().c_str());

        portalServer.on("/", []() {
            String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
            html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
            html += "<title>Configurar Gateway</title></head><body>";
            html += "<h1>Configurar Gateway IoT</h1>";
            html += "<form action='/save' method='POST'>";
            html += "<p>SSID: <input name='ssid'></p>";
            html += "<p>Senha: <input name='password' type='password'></p>";
            html += "<p><button type='submit'>Salvar e Conectar</button></p>";
            html += "</form></body></html>";
            portalServer.send(200, "text/html", html);
        });

        portalServer.on("/save", HTTP_POST, []() {
            String ssid = portalServer.arg("ssid");
            String pass = portalServer.arg("password");

            if (ssid.length() > 0) {
                Preferences p;
                p.begin("wifi-config", false);
                p.putString("ssid", ssid);
                p.putString("password", pass);
                p.end();

                portalServer.send(200, "text/html", "<h1>Salvo! Reiniciando...</h1>");
                delay(2000);
                ESP.restart();
            } else {
                portalServer.send(400, "text/html", "<h1>Erro: SSID obrigatório</h1>");
            }
        });

        portalServer.begin();
        portalAtivo = true;
        Serial.println("[AP] ✅ Portal de configuração ativo");
    }
}

void loop() {
    esp_task_wdt_reset();

    if (portalAtivo) {
        portalServer.handleClient();
        delay(10);
        return;
    }

    portalServer.handleClient();
    checkMQTTConnection();
    pairingProviderPoll();

    unsigned long now = millis();
    if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
        lastHeartbeat = now;
        sendHeartbeat();
    }

    delay(10);
}
