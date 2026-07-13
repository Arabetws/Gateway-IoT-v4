#pragma once
// provisioning_ap_mode.h
// Fluxo de pareamento "modo AP" para um device Tuya NOVO (ainda não
// configurado), análogo ao que o app oficial faz quando você escolhe
// "Modo AP" no cadastro.
//
// Sequência:
//   1. Usuário reseta o device físico -> ele sobe um AP próprio
//      (tipicamente algo como "SmartLife-XXXX" ou "SL-XXXX").
//   2. A ESP32-S3 escaneia redes, acha esse AP pelo prefixo do SSID.
//   3. ESP32-S3 troca STA temporariamente pra conectar nesse AP do device.
//   4. Envia POST com as credenciais da rede final pro endpoint local
//      do device (endereço/porta/payload PRECISAM ser confirmados via
//      captura de tráfego real — ver nota abaixo).
//   5. Device reinicia, conecta na rede final, e passa a aparecer nos
//      seus scans (network_scanner.h / tuya_discovery.h).
//   6. ESP32-S3 reconecta na rede WiFi original (a do gateway).
//
// ⚠️ IMPORTANTE PRA DEFESA DO TCC:
// O endpoint exato (path, porta, formato do payload) do modo AP varia
// por versão de firmware Tuya e NÃO está documentado publicamente de
// forma confiável — os projetos open-source (tinytuya, localtuya) que
// documentam o protocolo LAN (v3.3/v3.4/v3.5, que você já validou no
// tuya_v35.h) não cobrem o modo AP de primeira configuração da mesma
// forma. O caminho correto pra descobrir o payload real é capturar o
// tráfego do app oficial Tuya (Wireshark + celular na mesma rede, ou
// proxy MITM) enquanto ele faz o pareamento AP-mode com o SEU device
// físico, e documentar isso como parte da metodologia do TCC — é
// engenharia reversa legítima do SEU PRÓPRIO hardware, e fortalece a
// seção de metodologia (mostra que você validou empiricamente, igual
// fez com o GCM tag do RESP frame).

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "esp_task_wdt.h"
#include <Preferences.h>

extern NimBLEScan* bleScan;

namespace ApModeProvisioning {

struct Result {
    bool success;
    String message;
};

// Ajuste esse prefixo depois de ver o SSID real que seu device cria
// ao ser resetado (normalmente aparece no app oficial durante o pairing).
inline bool looksLikeUnconfiguredDevice(const String& ssid) {
    return ssid.startsWith("SmartLife-") || ssid.startsWith("SL-") || ssid.startsWith("Tuya-");
}

// Varre e retorna o SSID do primeiro device "virgem" encontrado, ou "" se nenhum.
inline String findUnconfiguredDevice() {
    int n = WiFi.scanNetworks(false, true, false, 300);
    String found = "";
    for (int i = 0; i < n; i++) {
        String ssid = WiFi.SSID(i);
        if (looksLikeUnconfiguredDevice(ssid)) {
            found = ssid;
            break;
        }
    }
    WiFi.scanDelete();
    return found;
}

// Executa o fluxo completo. targetSsid/targetPass = credenciais da
// rede final que o device deve usar (a mesma do gateway, tipicamente).
inline Result provision(const String& deviceApSsid, const String& targetSsid,
                         const String& targetPass, uint32_t connectTimeoutMs = 15000) {
    bool bleWasScanning = false;
    if (bleScan) {
        bleWasScanning = bleScan->isScanning();
        if (bleWasScanning) bleScan->stop();
    }
    // Salva a rede atual pra reconectar depois
    String originalSsid = WiFi.SSID();
 
    WiFi.disconnect();
    delay(200);
    WiFi.begin(deviceApSsid.c_str()); // APs de pareamento geralmente são abertos
 
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < connectTimeoutMs) {
        esp_task_wdt_reset();
        delay(300);
    }
 
    if (WiFi.status() != WL_CONNECTED) {
        Serial.printf("[PROVISION] ❌ WiFi.status() final = %d (0=IDLE,1=NO_SSID_AVAIL,3=CONNECTED,4=CONNECT_FAILED,6=DISCONNECTED)\n", (int)WiFi.status());
        Preferences pWifiFail;
        pWifiFail.begin("wifi-config", true);
        String failPass = pWifiFail.getString("password", "");
        pWifiFail.end();
        WiFi.disconnect();
        delay(200);
        WiFi.begin(originalSsid.c_str(), failPass.c_str());
        return {false, "Não conectou no AP do device"};
    }
 
    // ⚠️ ENDPOINT/PAYLOAD DE EXEMPLO — precisa ser confirmado por captura
    // real (ver nota no topo do arquivo).
    JsonDocument payload;
    payload["ssid"] = targetSsid;
    payload["passwd"] = targetPass;
    payload["token"] = "";
 
    String body;
    serializeJson(payload, body);
 
    HTTPClient http;
    bool sent = false;
    if (http.begin("http://192.168.1.1:8886/gw.json?a=s.town.subdev.wifi.config")) {
        http.addHeader("Content-Type", "application/json");
        int code = http.POST(body);
        sent = (code == 200);
        http.end();
    }
 
    // [FIX] Reconecta na rede original do gateway usando a SENHA salva
    // na NVS — WiFi.begin(ssid) sozinho nunca autentica numa rede WPA2.
    WiFi.disconnect();
    delay(200);
 
    Preferences pWifi;
    pWifi.begin("wifi-config", true);
    String originalPass = pWifi.getString("password", "");
    pWifi.end();
 
    WiFi.begin(originalSsid.c_str(), originalPass.c_str());
 
    uint32_t reconnectStart = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - reconnectStart < connectTimeoutMs) {
        esp_task_wdt_reset();
        delay(300);
    }
 
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[PROVISION] ⚠️ Falha ao reconectar na rede original após provisionar");
    } else {
        Serial.println("[PROVISION] ✅ Reconectado na rede original do gateway");
    }
 
    return sent
        ? Result{true, "Credenciais enviadas, aguardando device reiniciar na rede final"}
        : Result{false, "Falha ao enviar credenciais pro device"};
}


} // namespace ApModeProvisioning
