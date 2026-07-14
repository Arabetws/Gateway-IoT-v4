#pragma once

/**
 * provisioning_ap_mode.h — Provisionamento AP-mode para dispositivos Tuya
 * ======================================================================
 * 
 * Fluxo de pareamento "Modo AP" para dispositivos Tuya NOVOS ou resetados.
 * 
 * CORREÇÕES v2.0:
 *   • [FIX] Watchdog reset em todos os loops longos
 *   • [FIX] HTTP timeout reduzido para 3s
 *   • [FIX] Endpoint com IP dinâmico (usa gateway da rede do dispositivo)
 *   • [FIX] Delay reduzido entre tentativas
 *   • [FIX] Reconexão WiFi com watchdog
 */

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <vector>

// Forward declaration
extern NimBLEScan* bleScan;

namespace ApModeProvisioning {

// =====================================================================
// CONFIGURAÇÕES
// =====================================================================

struct Config {
    // Prefixos de SSID de dispositivos Tuya em modo AP
    std::vector<String> apPrefixes = {"SmartLife-", "SL-", "Tuya-"};
    
    // Endpoints de provisionamento (tentados em ordem)
    struct Endpoint {
        String ip;
        uint16_t port;
        String path;
    };
    
    // Timeouts (ms)
    uint32_t connectTimeoutMs = 15000;    // Reduzido de 20s para 15s
    uint32_t httpTimeoutMs = 3000;        // Reduzido de 5s para 3s
    uint32_t reconnectTimeoutMs = 20000;  // Reduzido de 30s para 20s
    
    // Retentativas por endpoint
    uint8_t maxRetries = 1;              // Reduzido de 2 para 1 (mais rápido)
};

// =====================================================================
// RESULTADO
// =====================================================================

struct Result {
    bool success;
    String message;
    int httpCode;
    String httpResponse;
    
    Result() : success(false), message(""), httpCode(0), httpResponse("") {}
    Result(bool s, const String& m, int c = 0, const String& r = "") 
        : success(s), message(m), httpCode(c), httpResponse(r) {}
    
    static Result ok(const String& msg = "OK") {
        return Result(true, msg, 200, "");
    }
    
    static Result fail(const String& msg, int code = 0) {
        return Result(false, msg, code, "");
    }
};

// =====================================================================
// UTILITÁRIOS
// =====================================================================

namespace Utils {

class WifiCredentials {
public:
    static bool save(const String& ssid, const String& password) {
        Preferences prefs;
        if (!prefs.begin("wifi-config", false)) return false;
        prefs.putString("ssid", ssid);
        prefs.putString("password", password);
        prefs.end();
        return true;
    }
    
    static String getSsid() {
        Preferences prefs;
        prefs.begin("wifi-config", true);
        String s = prefs.getString("ssid", "");
        prefs.end();
        return s;
    }
    
    static String getPassword() {
        Preferences prefs;
        prefs.begin("wifi-config", true);
        String p = prefs.getString("password", "");
        prefs.end();
        return p;
    }
};

class BLEScannerGuard {
private:
    bool wasScanning;
public:
    BLEScannerGuard() : wasScanning(false) {
        if (bleScan) {
            wasScanning = bleScan->isScanning();
            if (wasScanning) {
                bleScan->stop();
                delay(100);
            }
        }
    }
    
    ~BLEScannerGuard() {
        if (bleScan && wasScanning) {
            bleScan->start(0, nullptr, false);
        }
    }
};

bool reconnectToOriginal(const String& ssid, const String& password, 
                         uint32_t timeoutMs = 20000) {
    WiFi.disconnect(true);
    delay(300);
    
    WiFi.begin(ssid.c_str(), password.c_str());
    
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start) < timeoutMs) {
        delay(300);
        yield();
        esp_task_wdt_reset();  // ← Watchdog
    }
    
    return WiFi.status() == WL_CONNECTED;
}

} // namespace Utils

// =====================================================================
// DETECÇÃO DE DISPOSITIVOS
// =====================================================================

struct DeviceInfo {
    String ssid;
    uint8_t bssid[6];
    int32_t channel;
    int32_t rssi;
    bool found;
    
    DeviceInfo() : channel(0), rssi(0), found(false) {
        memset(bssid, 0, sizeof(bssid));
    }
};

bool isUnconfiguredDevice(const String& ssid, const Config& cfg = Config()) {
    if (ssid.length() < 3) return false;
    for (const auto& prefix : cfg.apPrefixes) {
        if (ssid.startsWith(prefix)) return true;
    }
    return false;
}

DeviceInfo findUnconfiguredDevice(const Config& cfg = Config()) {
    DeviceInfo info;
    
    int n = WiFi.scanNetworks(false, true, false, 400);
    
    for (int i = 0; i < n; i++) {
        String ssid = WiFi.SSID(i);
        if (isUnconfiguredDevice(ssid, cfg)) {
            info.ssid = ssid;
            info.channel = WiFi.channel(i);
            info.rssi = WiFi.RSSI(i);
            memcpy(info.bssid, WiFi.BSSID(i), 6);
            info.found = true;
            break;
        }
    }
    
    WiFi.scanDelete();
    return info;
}

std::vector<DeviceInfo> findAllUnconfiguredDevices(const Config& cfg = Config()) {
    std::vector<DeviceInfo> devices;
    
    int n = WiFi.scanNetworks(false, true, false, 400);
    
    for (int i = 0; i < n; i++) {
        String ssid = WiFi.SSID(i);
        if (isUnconfiguredDevice(ssid, cfg)) {
            DeviceInfo info;
            info.ssid = ssid;
            info.channel = WiFi.channel(i);
            info.rssi = WiFi.RSSI(i);
            memcpy(info.bssid, WiFi.BSSID(i), 6);
            info.found = true;
            devices.push_back(info);
        }
    }
    
    WiFi.scanDelete();
    return devices;
}

// =====================================================================
// CONEXÃO AO AP DO DISPOSITIVO
// =====================================================================

enum class ConnectionStrategy {
    BSSID_CHANNEL,
    SSID_ONLY
};

struct ConnectionResult {
    bool connected;
    ConnectionStrategy strategy;
    int wifiStatus;
    String localIP;
    
    ConnectionResult() : connected(false), strategy(ConnectionStrategy::SSID_ONLY), wifiStatus(0) {}
};

ConnectionResult connectToDeviceAP(const String& ssid, 
                                   const uint8_t* bssid = nullptr,
                                   int32_t channel = 0,
                                   uint32_t timeoutMs = 15000) {
    ConnectionResult result;
    
    // Estratégia 1: Conexão pinada (BSSID + canal) - mais rápida
    if (bssid != nullptr && channel > 0) {
        Serial.println("[AP-MODE] 📡 Tentativa 1: Conexão pinada...");
        result.strategy = ConnectionStrategy::BSSID_CHANNEL;
        
        WiFi.disconnect(false);
        delay(300);
        esp_task_wdt_reset();
        
        WiFi.begin(ssid.c_str(), nullptr, channel, bssid);
        
        uint32_t start = millis();
        while (WiFi.status() != WL_CONNECTED && (millis() - start) < timeoutMs) {
            delay(200);
            yield();
            esp_task_wdt_reset();  // ← Watchdog
        }
        
        result.connected = (WiFi.status() == WL_CONNECTED);
        result.wifiStatus = WiFi.status();
        
        if (result.connected) {
            result.localIP = WiFi.localIP().toString();
            Serial.printf("[AP-MODE] ✅ Conectado! IP: %s\n", result.localIP.c_str());
            return result;
        }
        
        Serial.printf("[AP-MODE] ⚠️ Pinada falhou (status=%d)\n", result.wifiStatus);
    }
    
    // Estratégia 2: Conexão por SSID apenas - mais confiável
    Serial.println("[AP-MODE] 📡 Tentativa: Conexão por SSID...");
    result.strategy = ConnectionStrategy::SSID_ONLY;
    
    WiFi.disconnect(false);
    delay(300);
    esp_task_wdt_reset();
    
    WiFi.begin(ssid.c_str(), nullptr);
    
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start) < timeoutMs) {
        delay(200);
        yield();
        esp_task_wdt_reset();  // ← Watchdog
    }
    
    result.connected = (WiFi.status() == WL_CONNECTED);
    result.wifiStatus = WiFi.status();
    
    if (result.connected) {
        result.localIP = WiFi.localIP().toString();
        Serial.printf("[AP-MODE] ✅ Conectado! IP: %s\n", result.localIP.c_str());
    } else {
        Serial.printf("[AP-MODE] ❌ Falhou (status=%d)\n", result.wifiStatus);
    }
    
    return result;
}

// =====================================================================
// ENVIO DE CREDENCIAIS (COM WATCHDOG)
// =====================================================================

/**
 * Extrai o gateway da rede (X.X.X.1) a partir do IP local
 */
String getGatewayFromIP(const String& localIP) {
    int lastDot = localIP.lastIndexOf('.');
    if (lastDot > 0) {
        return localIP.substring(0, lastDot) + ".1";
    }
    return "192.168.1.1";  // fallback
}

Result sendCredentials(const String& targetSsid, const String& targetPass,
                       const Config& cfg = Config()) {
    
    JsonDocument payload;
    payload["ssid"] = targetSsid;
    payload["passwd"] = targetPass;
    payload["token"] = "";
    
    String body;
    serializeJson(payload, body);
    
    Serial.printf("[AP-MODE] 📤 Enviando credenciais para '%s'\n", targetSsid.c_str());
    
    // Obtém o IP do gateway (dispositivo Tuya geralmente é X.X.X.1)
    String localIP = WiFi.localIP().toString();
    String gatewayIP = getGatewayFromIP(localIP);
    
    // Lista de endpoints para tentar (usa o gateway real descoberto)
    std::vector<Config::Endpoint> endpoints = {
        {gatewayIP,     8886, "/gw.json?a=s.town.subdev.wifi.config"},
        {gatewayIP,     80,   "/v1/device/config"},
        {"192.168.1.1", 8886, "/gw.json?a=s.town.subdev.wifi.config"},
        {"192.168.175.1", 80, "/v1/device/config"},
    };
    
    for (const auto& ep : endpoints) {
        esp_task_wdt_reset();  // ← Watchdog antes de cada endpoint
        
        HTTPClient http;
        
        String url = "http://" + ep.ip + ":" + String(ep.port) + ep.path;
        
        Serial.printf("[AP-MODE]    → %s\n", url.c_str());
        
        if (!http.begin(url)) {
            Serial.println("[AP-MODE]    ❌ http.begin() falhou");
            continue;
        }
        
        http.setTimeout(cfg.httpTimeoutMs);  // 3 segundos
        http.addHeader("Content-Type", "application/json");
        
        int code = http.POST(body);
        String response = http.getString();
        http.end();
        
        esp_task_wdt_reset();  // ← Watchdog depois do HTTP
        
        Serial.printf("[AP-MODE]    Resposta: HTTP %d\n", code);
        
        if (code == 200) {
            Serial.println("[AP-MODE] ✅ Credenciais enviadas com sucesso!");
            return Result::ok("Credenciais enviadas");
        }
        
        if (code > 0) {
            Serial.printf("[AP-MODE]    Corpo: %s\n", response.c_str());
        }
        
        delay(200);
        esp_task_wdt_reset();  // ← Watchdog
    }
    
    return Result::fail("Nenhum endpoint respondeu (gateway: " + gatewayIP + ")");
}

// =====================================================================
// FLUXO PRINCIPAL
// =====================================================================

Result provision(const String& deviceApSsid, 
                const String& targetSsid,
                const String& targetPass,
                uint32_t timeoutMs = 15000,
                const uint8_t* bssid = nullptr, 
                int32_t channel = 0) {
    
    Serial.println("\n╔══════════════════════════════════════════╗");
    Serial.println("║   TUYA AP-MODE PROVISIONING v2.0         ║");
    Serial.println("╚══════════════════════════════════════════╝");
    Serial.printf("  Dispositivo: %s\n", deviceApSsid.c_str());
    Serial.printf("  Rede final:  %s\n", targetSsid.c_str());
    
    Config cfg;
    cfg.connectTimeoutMs = timeoutMs;
    
    // 1. Salva estado atual
    Utils::BLEScannerGuard bleGuard;
    String originalSsid = Utils::WifiCredentials::getSsid();
    String originalPass = Utils::WifiCredentials::getPassword();
    
    esp_task_wdt_reset();  // ← Watchdog
    
    // 2. Conecta no AP do dispositivo
    auto connResult = connectToDeviceAP(deviceApSsid, bssid, channel, cfg.connectTimeoutMs);
    
    esp_task_wdt_reset();  // ← Watchdog
    
    if (!connResult.connected) {
        Serial.println("[AP-MODE] ❌ Falha na conexão com AP do dispositivo");
        Utils::reconnectToOriginal(originalSsid, originalPass);
        return Result::fail("Falha na conexão (status=" + String(connResult.wifiStatus) + ")");
    }
    
    // 3. Envia credenciais
    Result sendResult = sendCredentials(targetSsid, targetPass, cfg);
    
    esp_task_wdt_reset();  // ← Watchdog
    
    // 4. Reconecta na rede original
    Serial.println("[AP-MODE] 🔄 Reconectando na rede original...");
    
    if (!Utils::reconnectToOriginal(originalSsid, originalPass, cfg.reconnectTimeoutMs)) {
        Serial.println("[AP-MODE] ⚠️ Falha ao reconectar!");
        return Result::fail("Credenciais enviadas, mas gateway offline");
    }
    
    Serial.printf("[AP-MODE] ✅ Reconectado! IP: %s\n", WiFi.localIP().toString().c_str());
    
    if (sendResult.success) {
        Serial.println("[AP-MODE] 🎉 Provisionamento concluído!");
    } else {
        Serial.println("[AP-MODE] ⚠️ Provisionamento com ressalvas");
    }
    
    return sendResult;
}

Result provisionFirstAvailable(const String& targetSsid, const String& targetPass) {
    auto device = findUnconfiguredDevice();
    
    if (!device.found) {
        return Result::fail("Nenhum dispositivo Tuya em modo AP encontrado");
    }
    
    return provision(device.ssid, targetSsid, targetPass, 15000, device.bssid, device.channel);
}

} // namespace ApModeProvisioning
