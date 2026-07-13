#pragma once
// tuya_cloud_client.h
// Fallback: quando a descoberta passiva (tuya_discovery.h) acha um gwId novo
// pra que a gente ainda não tem local_key salva, busca a key na Tuya Cloud
// (API Open Platform) usando as credenciais do seu projeto (apiKey/apiSecret
// que você já tem no tuya-raw.json).
//
// Fluxo (assinatura HMAC-SHA256 conforme spec da Tuya Open API):
//   1. POST /v1.0/token?grant_type=1   -> access_token
//   2. GET  /v1.0/devices/{device_id}  -> local_key, ip, etc (usa access_token)
//
// IMPORTANTE: client_id/secret/access_token nunca devem ir pro repositório
// público do TCC. Carregue via NVS/Preferences ou secrets.h no .gitignore.

#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>

namespace TuyaCloud {

struct Credentials {
    String clientId;      // apiKey
    String clientSecret;  // apiSecret
    String host = "openapi.tuyaus.com"; // troque pra sua região (us/eu/cn/in)
};

inline String hmacSha256Hex(const String& key, const String& msg) {
    uint8_t hmacResult[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02X", hmacResult[i]);
    hex[64] = 0;
    return String(hex);
}

inline String sha256Hex(const String& msg) {
    uint8_t hash[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
    mbedtls_md_finish(&ctx, hash);
    mbedtls_md_free(&ctx);

    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = 0;
    return String(hex);
}

// Usa o epoch real via NTP (seu firmware já faz NTP/TLS hardening no gateway,
// então isso só funciona depois que o time() estiver sincronizado).
inline String nowMs() {
    time_t now = time(nullptr);
    return String((uint64_t)now * 1000ULL);
}

// Assina conforme spec: str = client_id + [access_token] + t + nonce + stringToSign
// stringToSign = METHOD\n + sha256(body)\n + headers\n + url
inline String sign(const Credentials& c, const String& method, const String& url,
                    const String& body, const String& accessToken, const String& t) {
    String contentHash = sha256Hex(body);
    String stringToSign = method + "\n" + contentHash + "\n\n" + url;
    String str = c.clientId + accessToken + t + stringToSign;
    return hmacSha256Hex(c.clientSecret, str);
}

// Passo 1: pega access_token
inline bool fetchAccessToken(const Credentials& c, String& accessTokenOut) {
    WiFiClientSecure client;
    client.setInsecure(); // TODO: pinar o certificado da Tuya em produção
    HTTPClient https;

    String url = "/v1.0/token?grant_type=1";
    String t = nowMs();
    String signature = sign(c, "GET", url, "", "", t);

    String fullUrl = "https://" + c.host + url;
    if (!https.begin(client, fullUrl)) return false;

    https.addHeader("client_id", c.clientId);
    https.addHeader("sign", signature);
    https.addHeader("t", t);
    https.addHeader("sign_method", "HMAC-SHA256");

    int code = https.GET();
    if (code != 200) { https.end(); return false; }

    JsonDocument doc;
    deserializeJson(doc, https.getString());
    https.end();

    if (!doc["success"].as<bool>()) return false;
    accessTokenOut = doc["result"]["access_token"].as<String>();
    return true;
}

// Passo 2: busca local_key + ip pelo device_id
inline bool fetchDeviceLocalKey(const Credentials& c, const String& accessToken,
                                 const String& deviceId, String& localKeyOut, String& ipOut) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient https;

    String url = "/v1.0/devices/" + deviceId;
    String t = nowMs();
    String signature = sign(c, "GET", url, "", accessToken, t);

    String fullUrl = "https://" + c.host + url;
    if (!https.begin(client, fullUrl)) return false;

    https.addHeader("client_id", c.clientId);
    https.addHeader("access_token", accessToken);
    https.addHeader("sign", signature);
    https.addHeader("t", t);
    https.addHeader("sign_method", "HMAC-SHA256");

    int code = https.GET();
    if (code != 200) { https.end(); return false; }

    JsonDocument doc;
    deserializeJson(doc, https.getString());
    https.end();

    if (!doc["success"].as<bool>()) return false;
    localKeyOut = doc["result"]["local_key"].as<String>();
    ipOut = doc["result"]["ip"].as<String>();
    return true;
}

// Wrapper de conveniência: token + device num único call.
inline bool resolveLocalKey(const Credentials& c, const String& deviceId,
                             String& localKeyOut, String& ipOut) {
    String token;
    if (!fetchAccessToken(c, token)) return false;
    return fetchDeviceLocalKey(c, token, deviceId, localKeyOut, ipOut);
}

} // namespace TuyaCloud
