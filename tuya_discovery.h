#pragma once
// tuya_discovery.h
// Escuta os broadcasts UDP que qualquer dispositivo Tuya local emite
// periodicamente na rede (mesmo protocolo que o tinytuya usa pra "scan").
//
// Porta 6666 -> pacote em JSON puro (protocolo antigo, ainda usado por
//               alguns firmwares em paralelo).
// Porta 6667 -> pacote em JSON criptografado com AES-128-ECB usando uma
//               chave FIXA e pública (md5("yGAdlopoPVldABfn")), documentada
//               no projeto tinytuya/localtuya. Não é segredo do dispositivo,
//               é uma chave de transporte fixa do protocolo de descoberta.
//
// Isso te dá: gwId, ip, active, ability, mode, encrypt, productKey, version
// — mas NÃO te dá o local_key (esse só vem da Tuya Cloud API, ver
// tuya_cloud_client.h). Ou seja: descoberta passiva acha "existe um Tuya
// aqui, nesse IP, com esse productKey/gwId" — o pareamento completo (poder
// mandar comando) só fecha depois de buscar a key na nuvem uma vez.

#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <mbedtls/aes.h>
#include <mbedtls/md5.h>
#include <functional>

namespace TuyaDiscovery {

struct TuyaBroadcastInfo {
    String gwId;
    String ip;
    String productKey;
    String version;
    bool encrypt;
};

using FoundCb = std::function<void(const TuyaBroadcastInfo&)>;

static WiFiUDP udp6666;
static WiFiUDP udp6667;

inline void deriveUdpKey(uint8_t out16[16]) {
    const char* seed = "yGAdlopoPVldABfn";
    mbedtls_md5((const unsigned char*)seed, strlen(seed), out16);
}

// Decripta um buffer AES-128-ECB (sem IV, padding PKCS7) usando a UDP key fixa.
inline String decryptEcb(const uint8_t* data, size_t len) {
    uint8_t key[16];
    deriveUdpKey(key);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);

    if (len % 16 != 0) { mbedtls_aes_free(&aes); return ""; }

    uint8_t* out = (uint8_t*)malloc(len + 1);
    for (size_t i = 0; i < len; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, data + i, out + i);
    }
    mbedtls_aes_free(&aes);

    // Remove padding PKCS7
    uint8_t pad = out[len - 1];
    size_t realLen = (pad <= 16) ? len - pad : len;
    out[realLen] = '\0';

    String result((char*)out);
    free(out);
    return result;
}

inline void begin() {
    udp6666.begin(6666);
    udp6667.begin(6667);
}

// Chame isso periodicamente no loop() — não bloqueia se não houver pacote.
inline void poll(FoundCb onFound) {
    uint8_t buf[512];

    int len6666 = udp6666.parsePacket();
    if (len6666 > 0) {
        int n = udp6666.read(buf, sizeof(buf) - 1);
        buf[n] = 0;
        JsonDocument doc;
        if (deserializeJson(doc, (char*)buf) == DeserializationError::Ok) {
            TuyaBroadcastInfo info;
            info.gwId = doc["gwId"] | "";
            info.ip = doc["ip"] | "";
            info.productKey = doc["productKey"] | "";
            info.version = doc["version"] | "";
            info.encrypt = doc["encrypt"] | false;
            if (info.gwId.length()) onFound(info);
        }
    }

    int len6667 = udp6667.parsePacket();
    if (len6667 > 0 && len6667 <= (int)sizeof(buf)) {
        int n = udp6667.read(buf, len6667);
        // Os primeiros bytes podem incluir um prefixo de versão antes do
        // bloco cifrado dependendo do firmware; na prática o payload todo
        // costuma já ser o bloco AES. Se vier "vazio"/lixo, tenta pular
        // os 4 primeiros bytes (variante observada em alguns devices).
        String json = decryptEcb(buf, n);
        if (!json.length()) json = decryptEcb(buf + 4, n - 4);

        JsonDocument doc;
        if (json.length() && deserializeJson(doc, json) == DeserializationError::Ok) {
            TuyaBroadcastInfo info;
            info.gwId = doc["gwId"] | "";
            info.ip = doc["ip"] | "";
            info.productKey = doc["productKey"] | "";
            info.version = doc["version"] | "";
            info.encrypt = doc["encrypt"] | true;
            if (info.gwId.length()) onFound(info);
        }
    }
}

} // namespace TuyaDiscovery
