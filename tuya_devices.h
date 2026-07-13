// =====================================================
// tuya_devices.h — Tabela de dispositivos Tuya + persistência (NVS)
// ─────────────────────────────────────────────────
// Define os tipos que tuya_v35.h espera encontrar ANTES do include
// (MAX_IOT_DEVICES, IotDevice, TUYA_CMD_PORT), e adiciona persistência
// em NVS (Preferences) pra não perder a tabela a cada reboot.
//
// IMPORTANTE: inclua este arquivo ANTES de "tuya_v35.h" no main.cpp.
// Se devices.h já define algo chamado IotDevice, precisa reconciliar
// os dois (renomear um dos dois) antes de compilar.
// =====================================================

#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <ArduinoJson.h>

#define MAX_IOT_DEVICES 16
#define TUYA_CMD_PORT   6668

enum class IotProtocol : uint8_t {
    TUYA_V33 = 0,
    TUYA_V34 = 1,
    TUYA_V35 = 2,
    UNKNOWN  = 255
};

struct IotDevice {
    char        id[24];      // gwId da Tuya (ex: "eb36e8f1d53a808ac2puil")
    char        ip[16];
    uint8_t     localKey[16];
    IotProtocol protocol;
    int         dpId;        // data point principal a controlar (ex: 20 = switch_led)
    bool        online;
};

static IotDevice iotDevices[MAX_IOT_DEVICES];
static uint8_t   iotDeviceCount = 0;

int findIotDeviceById(const char* id) {
    for (uint8_t i = 0; i < iotDeviceCount; i++) {
        if (strcmp(iotDevices[i].id, id) == 0) return i;
    }
    return -1;
}

// Registra um device novo ou atualiza um existente com o mesmo id.
// Usado tanto ao carregar da NVS no boot quanto ao concluir um pareamento.
bool registerIotDevice(const char* id, const char* ip, const uint8_t* localKey16,
                        IotProtocol protocol, int dpId) {
    int idx = findIotDeviceById(id);
    if (idx < 0) {
        if (iotDeviceCount >= MAX_IOT_DEVICES) {
            Serial.println("[IOT] ❌ Tabela de dispositivos cheia");
            return false;
        }
        idx = iotDeviceCount++;
    }
    strncpy(iotDevices[idx].id, id, sizeof(iotDevices[idx].id) - 1);
    iotDevices[idx].id[sizeof(iotDevices[idx].id) - 1] = '\0';
    strncpy(iotDevices[idx].ip, ip, sizeof(iotDevices[idx].ip) - 1);
    iotDevices[idx].ip[sizeof(iotDevices[idx].ip) - 1] = '\0';
    memcpy(iotDevices[idx].localKey, localKey16, 16);
    iotDevices[idx].protocol = protocol;
    iotDevices[idx].dpId = dpId;
    iotDevices[idx].online = true;
    return true;
}

bool removeIotDevice(const char* id) {
    int idx = findIotDeviceById(id);
    if (idx < 0) return false;
    for (uint8_t i = idx; i < iotDeviceCount - 1; i++) iotDevices[i] = iotDevices[i + 1];
    iotDeviceCount--;
    return true;
}

void saveIotDevicesToNVS() {
    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();
    for (uint8_t i = 0; i < iotDeviceCount; i++) {
        JsonObject o = arr.add<JsonObject>();
        o["id"] = iotDevices[i].id;
        o["ip"] = iotDevices[i].ip;
        char keyHex[33];
        for (int j = 0; j < 16; j++) sprintf(keyHex + j * 2, "%02x", iotDevices[i].localKey[j]);
        keyHex[32] = '\0';
        o["key"] = keyHex;
        o["protocol"] = (int)iotDevices[i].protocol;
        o["dpId"] = iotDevices[i].dpId;
    }
    String out;
    serializeJson(doc, out);

    Preferences p;
    p.begin("iot-devices", false);
    p.putString("list", out);
    p.end();

    Serial.printf("[IOT] 💾 %d dispositivo(s) salvo(s) na NVS\n", iotDeviceCount);
}

void loadIotDevicesFromNVS() {
    Preferences p;
    p.begin("iot-devices", true);
    String raw = p.getString("list", "[]");
    p.end();

    JsonDocument doc;
    if (deserializeJson(doc, raw)) {
        Serial.println("[IOT] ⚠️ Falha ao ler tabela de dispositivos da NVS (usando vazia)");
        return;
    }

    iotDeviceCount = 0;
    for (JsonObject o : doc.as<JsonArray>()) {
        if (iotDeviceCount >= MAX_IOT_DEVICES) break;
        IotDevice& d = iotDevices[iotDeviceCount];

        const char* id = o["id"] | "";
        const char* ip = o["ip"] | "";
        strncpy(d.id, id, sizeof(d.id) - 1); d.id[sizeof(d.id) - 1] = '\0';
        strncpy(d.ip, ip, sizeof(d.ip) - 1); d.ip[sizeof(d.ip) - 1] = '\0';

        const char* keyHex = o["key"] | "";
        if (strlen(keyHex) >= 32) {
            for (int j = 0; j < 16; j++) {
                char b[3] = { keyHex[j * 2], keyHex[j * 2 + 1], 0 };
                d.localKey[j] = (uint8_t)strtol(b, nullptr, 16);
            }
        } else {
            memset(d.localKey, 0, 16);
        }

        d.protocol = (IotProtocol)(int)(o["protocol"] | (int)IotProtocol::TUYA_V35);
        d.dpId = o["dpId"] | 20;
        d.online = true;
        iotDeviceCount++;
    }
    Serial.printf("[IOT] 📂 %d dispositivo(s) carregado(s) da NVS\n", iotDeviceCount);
}
