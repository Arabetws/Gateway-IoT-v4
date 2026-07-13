// =====================================================
// tuya_dispatch.h — Roteamento de comandos por protocolo
// ─────────────────────────────────────────────────
// Inclua DEPOIS de tuya_devices.h e tuya_v35.h no main.cpp.
// =====================================================

#pragma once
#include "tuya_devices.h"
#include "tuya_v35.h"

// Ponto único chamado pelo processControl() do gateway.
// Retorna false se o device não existe ou o protocolo não está
// implementado ainda (ex: v3.3 legado).
bool dispatchIotCommand(const char* deviceId, bool turnOn) {
    int idx = findIotDeviceById(deviceId);
    if (idx < 0) {
        Serial.printf("[IOT] ❌ Dispositivo desconhecido: %s\n", deviceId);
        return false;
    }

    IotDevice& dev = iotDevices[idx];

    switch (dev.protocol) {
        case IotProtocol::TUYA_V35:
        case IotProtocol::TUYA_V34:
            return tuyaSetSwitchV35(dev, turnOn, dev.dpId, (uint8_t)idx);

        case IotProtocol::TUYA_V33:
            // TODO: plugar o driver v3.3 (AES-ECB, sem handshake) aqui quando
            // for integrá-lo — ele é bem mais simples que o v3.5.
            Serial.println("[IOT] ⚠️ Driver v3.3 ainda não integrado neste dispatch");
            return false;

        default:
            Serial.println("[IOT] ❌ Protocolo desconhecido para este dispositivo");
            return false;
    }
}
