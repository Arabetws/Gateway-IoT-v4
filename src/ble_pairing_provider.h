#pragma once
// =====================================================
// ble_pairing_provider.h
// Pareamento BLE genérico via NimBLE Security Manager.
// Compatível com: NimBLE-Arduino @ ^1.4.3 (API pré-2.x)
// Depende de: bleDevs[]/bleDevCount/bleScan (definidos no
//             main.cpp, preenchidos pelo último runScanBLE())
//             e esp_task_wdt_reset() (esp_task_wdt.h).
// ─────────────────────────────────────────────────
// IMPORTANTE — ONDE DAR #include NESTE HEADER:
// bleDevs/bleDevCount/bleScan são `static` no main.cpp (linkage
// interno do arquivo), e struct BLEDev só existe depois de
// definida. Por isso este header NÃO declara nada disso via
// extern/forward-declare (isso quebra a build — foi tentado e
// deu erro de "incomplete type" + conflito static/extern).
// Em vez disso, dê #include "ble_pairing_provider.h" DEPOIS do
// bloco "SCAN BLE" do main.cpp (depois de "NimBLEScan* bleScan
// = nullptr;" e de runScanBLE()/publishBLEScan()), e ANTES da
// seção "// PAREAMENTO". Assim BLEDev, bleDevs, bleDevCount e
// bleScan já estão visíveis nesse ponto do arquivo, e este
// header não precisa (nem pode) redeclará-los.
// ─────────────────────────────────────────────────
// Uso (a partir de processPairing() no main.cpp):
//
//   BlePairing::PairResult r = BlePairing::pair(macStr);
//   // r.ok, r.step, r.message prontos pra montar a resposta MQTT
//
// NOTA: connect()/secureConnection() do NimBLEClient nesta
// versão são bloqueantes. Isso é consistente com o resto do
// firmware (runScanBLE(), connectWiFi() etc também bloqueiam),
// então NÃO há máquina de estados assíncrona aqui — o loop()
// principal fica bloqueado durante o pareamento (alguns
// segundos), com watchdog resetado manualmente ao longo do
// processo.
// =====================================================

#include <Arduino.h>
#include "NimBLEDevice.h"
#include "esp_task_wdt.h"

// SEM extern/forward-declare aqui de propósito — ver nota de
// posicionamento do #include no topo deste arquivo. BLEDev,
// bleDevs, bleDevCount e bleScan precisam já estar definidos
// no main.cpp acima do ponto onde este header é incluído.

namespace BlePairing {

struct PairResult {
    bool   ok;
    const char* step;   // "validation" | "connect" | "secure" | "bonded"
    String message;
};

// ─────────────────────────────────────────────────
// Callbacks do client — versão NimBLE-Arduino 1.4.x
// (onAuthenticationComplete recebe ble_gap_conn_desc*,
// NÃO NimBLEConnInfo& como na branch 2.x)
// ─────────────────────────────────────────────────
static volatile bool s_authComplete = false;
static volatile bool s_authBonded   = false;

class PairingClientCallbacks : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient* pc) override {
        Serial.println("[PAIR] 🔗 Conectado ao peer, aguardando handshake de seguranca...");
    }
    void onDisconnect(NimBLEClient* pc) override {
        Serial.println("[PAIR] 🔌 Desconectado do peer.");
    }
    void onAuthenticationComplete(ble_gap_conn_desc* desc) override {
        s_authBonded   = desc->sec_state.encrypted && desc->sec_state.bonded;
        s_authComplete = true;
        Serial.printf("[PAIR] 🔐 Autenticacao completa - encrypted=%d bonded=%d\n",
                      desc->sec_state.encrypted, desc->sec_state.bonded);
    }
};

static PairingClientCallbacks s_clientCB;

// Confere se o MAC apareceu no último scan_ble e retorna o tipo de
// endereço (public/random) — necessário pra montar o NimBLEAddress
// certo, e evita que a ESP32 tente conectar num MAC arbitrário que
// o site mande sem nunca ter sido visto por perto.
inline bool findScannedDevice(const char* mac, bool* isRandom) {
    for (uint8_t i = 0; i < bleDevCount; i++) {
        if (strcasecmp(bleDevs[i].mac, mac) == 0) {
            // OBS: campo macAleatorio já existe na struct BLEDev
            *isRandom = bleDevs[i].macAleatorio;
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────
// pair() — fluxo completo e bloqueante:
//   validar MAC -> parar scan -> criar client -> connect
//   -> secureConnection() -> aguardar onAuthenticationComplete
//   -> limpar client -> retornar resultado
// ─────────────────────────────────────────────────
inline PairResult pair(const char* macStr) {
    bool isRandom = false;
    if (!findScannedDevice(macStr, &isRandom)) {
        return { false, "validation",
                 "MAC nao encontrado no ultimo scan BLE - rode scan_ble antes de parear" };
    }

    // Scan ativo e conexao GAP competem pelo mesmo radio - para o
    // scan antes de tentar conectar.
    if (bleScan && bleScan->isScanning()) {
        bleScan->stop();
    }

    NimBLEAddress addr(std::string(macStr),
                        isRandom ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    pClient->setClientCallbacks(&s_clientCB, false);
    pClient->setConnectTimeout(10); // segundos

    Serial.printf("[PAIR] 🎯 Iniciando pareamento com %s (%s)\n",
                  macStr, isRandom ? "random" : "public");

    esp_task_wdt_reset();
    bool connected = pClient->connect(addr);
    esp_task_wdt_reset();

    if (!connected) {
        NimBLEDevice::deleteClient(pClient);
        return { false, "connect",
                 "Falha ao conectar ao dispositivo BLE (fora de alcance ou recusou a conexao)" };
    }

    // Reset das flags de autenticacao antes de disparar o handshake
    s_authComplete = false;
    s_authBonded   = false;

    esp_task_wdt_reset();
    bool secureCallOk = pClient->secureConnection();
    esp_task_wdt_reset();

    // Espera de seguranca adicional: secureConnection() deveria
    // bloquear ate a autenticacao terminar, mas aguardamos
    // explicitamente o callback tambem (com timeout) por garantia -
    // nao custa nada e cobre variacoes de comportamento entre
    // patch-versions da 1.4.x.
    uint32_t waitStart = millis();
    while (!s_authComplete && millis() - waitStart < 10000) {
        delay(20);
        esp_task_wdt_reset();
    }

    bool bonded = secureCallOk && s_authComplete && s_authBonded;

    if (pClient->isConnected()) {
        pClient->disconnect();
    }
    NimBLEDevice::deleteClient(pClient);

    if (bonded) {
        Serial.printf("[PAIR] ✅ Bond estabelecido com %s\n", macStr);
        return { true, "bonded", "Dispositivo pareado e bond salvo com sucesso" };
    }

    Serial.printf("[PAIR] ❌ Falha no bonding com %s\n", macStr);
    return { false, "secure", "Falha no handshake de seguranca / bonding" };
}

} // namespace BlePairing