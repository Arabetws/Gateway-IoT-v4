// =====================================================
// iot_drivers.h — Sistema de Drivers IoT Plugáveis (v2)
// ─────────────────────────────────────────────────
// Objetivo: dar ao gateway a capacidade de ESCANEAR a rede,
// CONECTAR e ENVIAR COMANDOS a dispositivos IoT já
// identificados, com reconexão automática quando o IP
// do dispositivo muda (DHCP) ou a primeira tentativa falha.
//
// Suporta hoje:
//   • TUYA_LOCAL   — protocolo LAN v3.3 (AES-128-ECB), usado pela
//                     maioria das lâmpadas/tomadas Tuya/SmartLife/
//                     Elgin Smart. Precisa de device_id + local_key
//                     (extraídos via tinytuya wizard).
//   • HTTP_GENERIC — dispositivos com API HTTP simples (Tasmota,
//                     Shelly, ESPHome native webserver).
//
// NOVO NESTA VERSÃO:
//   • scanNetworkForIotDevices() — escuta os broadcasts UDP que os
//     dispositivos Tuya emitem periodicamente (portas 6666/6667) e
//     atualiza o IP salvo sempre que ele muda, sem intervenção manual.
//   • ensureDeviceReachable() — antes de qualquer comando, valida que
//     o IP salvo ainda responde; se não responder, dispara um scan
//     rápido e tenta de novo antes de desistir.
//   • Retry com backoff simples em tuyaSendRaw()/httpSendCommand().
//   • Buffers com verificação de limite (evita overflow em payloads
//     grandes) e checagem de WiFi.status() antes de qualquer I/O.
//
// Arquitetura: cada dispositivo salvo tem um "tipo" de driver.
// O dispatch de comando é escolhido automaticamente por esse campo.
// Adicionar um novo fabricante = adicionar um novo "case" em
// dispatchIotCommand(), sem mexer no resto.
// =====================================================

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <mbedtls/aes.h>
#include <time.h>

// =====================================================
// CONFIGURAÇÃO / CONSTANTES
// =====================================================

#define MAX_IOT_DEVICES        16
#define TUYA_CMD_PORT           6668   // porta de comando (unicast TCP)
#define TUYA_UDP_PORT_LEGACY    6666   // broadcast texto puro (v3.1)
#define TUYA_UDP_PORT_ENCRYPTED 6667   // broadcast criptografado (v3.3/3.4)
#define IOT_SEND_MAX_RETRIES    2      // tentativas por comando
#define IOT_SEND_RETRY_DELAY_MS 400
#define IOT_TCP_PROBE_TIMEOUT_MS 800   // timeout curto só para checar alcançabilidade
#define IOT_SCAN_DEFAULT_WINDOW_MS 2500

// Chave fixa usada por TODOS os dispositivos Tuya para criptografar os
// broadcasts UDP de descoberta (não é a local_key do dispositivo — é
// pública e documentada no protocolo, igual ao projeto tinytuya).
// É o MD5("yGAdlopoPVldABfn") já pré-calculado — hardcodado em vez de
// calculado em runtime porque MBEDTLS_MD5_C não está habilitado neste
// build do Arduino/ESP-IDF (linker não acha mbedtls_md5_starts). Como
// a seed é uma constante fixa do protocolo, o hash também é fixo.
static const uint8_t TUYA_UDP_BROADCAST_KEY[16] = {
    0x6C, 0x1E, 0xC8, 0xE2, 0xBB, 0x9B, 0xB5, 0x9A,
    0xB5, 0x0B, 0x0D, 0xAF, 0x64, 0x9B, 0x41, 0x0A
};

// =====================================================
// TIPOS DE DRIVER
// =====================================================

enum IotDriverType : uint8_t {
    DRIVER_NONE         = 0,
    DRIVER_TUYA_LOCAL   = 1,
    DRIVER_HTTP_GENERIC = 2,
};

struct IotDevice {
    char name[32];
    char mac[18];
    char ip[16];
    IotDriverType tipo;

    // --- campos Tuya local ---
    char devId[24];
    char localKey[17]; // 16 bytes + \0
    uint8_t tuyaVersion; // 33 = v3.3

    // --- campos HTTP genérico ---
    char httpOnPath[64];   // ex: /cmnd/Power/ON
    char httpOffPath[64];  // ex: /cmnd/Power/OFF
    uint16_t httpPort;

    // --- estado de conectividade (não persistido) ---
    unsigned long lastSeenMs;   // último ping/scan/comando bem-sucedido
    uint8_t consecutiveFails;   // falhas seguidas (para backoff/alerta)

    bool valid;
};

static IotDevice iotDevices[MAX_IOT_DEVICES];
static uint8_t   iotDeviceCount = 0;
static WiFiUDP   tuyaUdp;

// =====================================================
// PERSISTÊNCIA (NVS via Preferences)
// =====================================================

void loadIotDevices() {
    Preferences p;
    p.begin("iot-devices", true);
    iotDeviceCount = p.getUChar("count", 0);
    if (iotDeviceCount > MAX_IOT_DEVICES) iotDeviceCount = MAX_IOT_DEVICES;
    for (uint8_t i = 0; i < iotDeviceCount; i++) {
        String prefix = "d" + String(i) + "_";
        String blob = p.getString((prefix + "blob").c_str(), "");
        if (blob.length() == 0) { iotDevices[i].valid = false; continue; }
        JsonDocument doc;
        if (deserializeJson(doc, blob)) { iotDevices[i].valid = false; continue; }
        IotDevice& d = iotDevices[i];
        strlcpy(d.name, doc["name"] | "", sizeof(d.name));
        strlcpy(d.mac,  doc["mac"]  | "", sizeof(d.mac));
        strlcpy(d.ip,   doc["ip"]   | "", sizeof(d.ip));
        d.tipo = (IotDriverType)(doc["tipo"] | 0);
        strlcpy(d.devId,    doc["devId"]    | "", sizeof(d.devId));
        strlcpy(d.localKey, doc["localKey"] | "", sizeof(d.localKey));
        d.tuyaVersion = doc["tuyaVersion"] | 33;
        strlcpy(d.httpOnPath,  doc["httpOnPath"]  | "", sizeof(d.httpOnPath));
        strlcpy(d.httpOffPath, doc["httpOffPath"] | "", sizeof(d.httpOffPath));
        d.httpPort = doc["httpPort"] | 80;
        d.lastSeenMs = 0;
        d.consecutiveFails = 0;
        d.valid = true;
    }
    p.end();
    Serial.printf("[IOT] 📦 %d dispositivos carregados da NVS\n", iotDeviceCount);
}

void saveIotDevice(uint8_t idx) {
    if (idx >= MAX_IOT_DEVICES) return;
    IotDevice& d = iotDevices[idx];
    JsonDocument doc;
    doc["name"] = d.name; doc["mac"] = d.mac; doc["ip"] = d.ip;
    doc["tipo"] = (int)d.tipo;
    doc["devId"] = d.devId; doc["localKey"] = d.localKey; doc["tuyaVersion"] = d.tuyaVersion;
    doc["httpOnPath"] = d.httpOnPath; doc["httpOffPath"] = d.httpOffPath; doc["httpPort"] = d.httpPort;
    String blob; serializeJson(doc, blob);

    Preferences p;
    p.begin("iot-devices", false);
    p.putString(("d" + String(idx) + "_blob").c_str(), blob);
    if (idx + 1 > p.getUChar("count", 0)) p.putUChar("count", idx + 1);
    p.end();
}

// Adiciona ou atualiza (por MAC) um dispositivo Tuya local
int registerTuyaDevice(const char* name, const char* mac, const char* ip,
                        const char* devId, const char* localKey, uint8_t version = 33) {
    int idx = -1;
    for (uint8_t i = 0; i < iotDeviceCount; i++) {
        if (iotDevices[i].valid && strcmp(iotDevices[i].mac, mac) == 0) { idx = i; break; }
    }
    if (idx == -1) {
        if (iotDeviceCount >= MAX_IOT_DEVICES) return -1;
        idx = iotDeviceCount++;
    }
    IotDevice& d = iotDevices[idx];
    strlcpy(d.name, name, sizeof(d.name));
    strlcpy(d.mac, mac, sizeof(d.mac));
    strlcpy(d.ip, ip, sizeof(d.ip));
    d.tipo = DRIVER_TUYA_LOCAL;
    strlcpy(d.devId, devId, sizeof(d.devId));
    strlcpy(d.localKey, localKey, sizeof(d.localKey));
    d.tuyaVersion = version;
    d.lastSeenMs = millis();
    d.consecutiveFails = 0;
    d.valid = true;
    saveIotDevice(idx);
    Serial.printf("[IOT] ✅ Dispositivo Tuya registrado: %s (%s)\n", name, ip);
    return idx;
}

int registerHttpDevice(const char* name, const char* mac, const char* ip,
                        const char* onPath, const char* offPath, uint16_t port = 80) {
    int idx = -1;
    for (uint8_t i = 0; i < iotDeviceCount; i++) {
        if (iotDevices[i].valid && strcmp(iotDevices[i].mac, mac) == 0) { idx = i; break; }
    }
    if (idx == -1) {
        if (iotDeviceCount >= MAX_IOT_DEVICES) return -1;
        idx = iotDeviceCount++;
    }
    IotDevice& d = iotDevices[idx];
    strlcpy(d.name, name, sizeof(d.name));
    strlcpy(d.mac, mac, sizeof(d.mac));
    strlcpy(d.ip, ip, sizeof(d.ip));
    d.tipo = DRIVER_HTTP_GENERIC;
    strlcpy(d.httpOnPath, onPath, sizeof(d.httpOnPath));
    strlcpy(d.httpOffPath, offPath, sizeof(d.httpOffPath));
    d.httpPort = port;
    d.lastSeenMs = millis();
    d.consecutiveFails = 0;
    d.valid = true;
    saveIotDevice(idx);
    Serial.printf("[IOT] ✅ Dispositivo HTTP registrado: %s (%s)\n", name, ip);
    return idx;
}

IotDevice* findIotDeviceByName(const char* name) {
    for (uint8_t i = 0; i < iotDeviceCount; i++)
        if (iotDevices[i].valid && strcmp(iotDevices[i].name, name) == 0) return &iotDevices[i];
    return nullptr;
}

IotDevice* findIotDeviceByDevId(const char* devId) {
    for (uint8_t i = 0; i < iotDeviceCount; i++)
        if (iotDevices[i].valid && iotDevices[i].tipo == DRIVER_TUYA_LOCAL &&
            strcmp(iotDevices[i].devId, devId) == 0) return &iotDevices[i];
    return nullptr;
}

// =====================================================
// CRIPTO — AES-128-ECB (com verificação de limites)
// =====================================================

static uint32_t tuyaCRC32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
    }
    return ~crc;
}

// AES-128-ECB com padding PKCS7. Retorna 0 se a entrada não couber no
// buffer de saída (evita overflow silencioso).
static size_t tuyaAesEncrypt(const uint8_t* key16, const uint8_t* input, size_t inLen,
                              uint8_t* out, size_t outCapacity) {
    size_t padded = ((inLen / 16) + 1) * 16;
    if (padded > outCapacity) {
        Serial.println("[TUYA] ❌ Payload grande demais para o buffer de criptografia");
        return 0;
    }
    uint8_t padVal = (uint8_t)(padded - inLen);

    static uint8_t buf[512];
    if (padded > sizeof(buf)) {
        Serial.println("[TUYA] ❌ Payload excede o limite interno de 512 bytes");
        return 0;
    }
    memcpy(buf, input, inLen);
    for (size_t i = inLen; i < padded; i++) buf[i] = padVal;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key16, 128);
    for (size_t i = 0; i < padded; i += 16)
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, buf + i, out + i);
    mbedtls_aes_free(&aes);
    return padded;
}

// AES-128-ECB decrypt SEM remover padding (o chamador trata o padding,
// já que o payload é JSON e dá para cortar no primeiro '\0' ou '}').
static size_t tuyaAesDecrypt(const uint8_t* key16, const uint8_t* input, size_t inLen,
                              uint8_t* out, size_t outCapacity) {
    if (inLen == 0 || inLen % 16 != 0 || inLen > outCapacity) return 0;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key16, 128);
    for (size_t i = 0; i < inLen; i += 16)
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, input + i, out + i);
    mbedtls_aes_free(&aes);
    return inLen;
}

// =====================================================
// 🔎 SCAN — descoberta/atualização de IP via broadcast UDP Tuya
// ─────────────────────────────────────────────────
// Dispositivos Tuya anunciam periodicamente sua presença via UDP
// broadcast nas portas 6666 (texto puro, protocolos antigos) e 6667
// (payload criptografado com a chave fixa TUYA_UDP_BROADCAST_KEY,
// protocolos 3.3/3.4). Escutamos essas portas por uma janela curta,
// decodificamos o JSON {gwId/devId, ip, version...} e, se o gwId bate
// com um dispositivo já cadastrado, atualizamos e persistimos o IP.
// =====================================================

// Extrai o payload JSON de um pacote no formato Tuya:
// [4B 0x000055AA][4B seq][4B cmd][4B len][payload...][4B crc][4B 0x0000AA55]
static bool tuyaExtractPayload(const uint8_t* pkt, size_t pktLen, const uint8_t** payloadOut, size_t* payloadLenOut) {
    if (pktLen < 16) return false;
    uint32_t prefix = ((uint32_t)pkt[0] << 24) | (pkt[1] << 16) | (pkt[2] << 8) | pkt[3];
    if (prefix != 0x000055AA) return false;
    uint32_t declaredLen = ((uint32_t)pkt[12] << 24) | (pkt[13] << 16) | (pkt[14] << 8) | pkt[15];
    // declaredLen inclui payload + crc(4) + suffix(4)
    if (declaredLen < 8 || 16 + declaredLen > pktLen) return false;
    size_t payloadLen = declaredLen - 8;
    if (payloadLen == 0 || payloadLen > pktLen - 16) return false;
    *payloadOut = pkt + 16;
    *payloadLenOut = payloadLen;
    return true;
}

// Processa um único pacote de broadcast recebido; retorna true se
// atualizou (ou confirmou) o IP de algum dispositivo cadastrado.
static bool tuyaProcessBroadcastPacket(const uint8_t* pkt, size_t pktLen, bool encrypted, IPAddress srcIp) {
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    if (!tuyaExtractPayload(pkt, pktLen, &payload, &payloadLen)) return false;

    static uint8_t decrypted[512];
    const char* jsonStart = nullptr;
    size_t jsonLen = 0;

    if (encrypted) {
        size_t dLen = tuyaAesDecrypt(TUYA_UDP_BROADCAST_KEY, payload, payloadLen, decrypted, sizeof(decrypted));
        if (dLen == 0) return false;
        jsonStart = (const char*)decrypted;
        jsonLen = dLen;
    } else {
        if (payloadLen > sizeof(decrypted)) return false;
        memcpy(decrypted, payload, payloadLen);
        jsonStart = (const char*)decrypted;
        jsonLen = payloadLen;
    }

    JsonDocument doc;
    // deserializeJson tolera padding PKCS7 sobrando após o '}' final
    if (deserializeJson(doc, jsonStart, jsonLen)) return false;

    const char* gwId = doc["gwId"] | doc["devId"] | (const char*)nullptr;
    if (!gwId) return false;

    IotDevice* dev = findIotDeviceByDevId(gwId);
    if (!dev) return false; // broadcast de um dispositivo que não é nosso

    String newIp = srcIp.toString();
    bool changed = strcmp(dev->ip, newIp.c_str()) != 0;
    strlcpy(dev->ip, newIp.c_str(), sizeof(dev->ip));
    dev->lastSeenMs = millis();
    dev->consecutiveFails = 0;

    if (changed) {
        for (uint8_t i = 0; i < iotDeviceCount; i++) {
            if (&iotDevices[i] == dev) { saveIotDevice(i); break; }
        }
        Serial.printf("[SCAN] 🔄 IP atualizado para %s → %s\n", dev->name, newIp.c_str());
    }
    return true;
}

// Escuta broadcasts Tuya por `windowMs` milissegundos. Retorna o
// número de dispositivos cadastrados vistos/atualizados nessa janela.
// Chame isso periodicamente (ex: a cada minuto) OU sob demanda quando
// um comando falhar por IP desatualizado (ver ensureDeviceReachable).
int scanNetworkForIotDevices(uint32_t windowMs = IOT_SCAN_DEFAULT_WINDOW_MS) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[SCAN] ⚠️ WiFi não conectado, abortando scan");
        return 0;
    }

    WiFiUDP udpLegacy, udpEnc;
    bool okLegacy = udpLegacy.begin(TUYA_UDP_PORT_LEGACY);
    bool okEnc    = udpEnc.begin(TUYA_UDP_PORT_ENCRYPTED);
    if (!okLegacy && !okEnc) {
        Serial.println("[SCAN] ❌ Não foi possível abrir as portas UDP de descoberta");
        return 0;
    }

    static uint8_t pktBuf[600];
    int updated = 0;
    unsigned long start = millis();

    while (millis() - start < windowMs) {
        if (okLegacy) {
            int sz = udpLegacy.parsePacket();
            if (sz > 0 && sz <= (int)sizeof(pktBuf)) {
                udpLegacy.read(pktBuf, sz);
                if (tuyaProcessBroadcastPacket(pktBuf, sz, /*encrypted=*/false, udpLegacy.remoteIP()))
                    updated++;
            }
        }
        if (okEnc) {
            int sz = udpEnc.parsePacket();
            if (sz > 0 && sz <= (int)sizeof(pktBuf)) {
                udpEnc.read(pktBuf, sz);
                if (tuyaProcessBroadcastPacket(pktBuf, sz, /*encrypted=*/true, udpEnc.remoteIP()))
                    updated++;
            }
        }
        delay(10);
    }

    udpLegacy.stop();
    udpEnc.stop();
    Serial.printf("[SCAN] 🔎 Janela de %lums concluída — %d dispositivo(s) confirmado(s)/atualizado(s)\n",
                  (unsigned long)windowMs, updated);
    return updated;
}

// =====================================================
// CONECTIVIDADE — checagem rápida + reconexão automática
// =====================================================

// Teste de alcançabilidade rápido: só confirma que dá para abrir uma
// conexão TCP na porta do dispositivo, sem enviar comando nenhum.
static bool probeTcp(const char* ip, uint16_t port, uint32_t timeoutMs = IOT_TCP_PROBE_TIMEOUT_MS) {
    WiFiClient client;
    client.setTimeout(timeoutMs);
    bool ok = client.connect(ip, port);
    if (ok) client.stop();
    return ok;
}

// Garante que o dispositivo está com um IP alcançável ANTES de enviar
// um comando. Se a checagem rápida falhar, dispara um scan (Tuya) e
// tenta de novo com o IP possivelmente atualizado. Para HTTP genérico,
// não há broadcast padrão de descoberta, então apenas reavaliamos a
// conectividade e sinalizamos no log se o dispositivo parece offline.
bool ensureDeviceReachable(IotDevice& dev) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[IOT] ⚠️ Gateway sem WiFi — não é possível alcançar dispositivos");
        return false;
    }

    uint16_t port = (dev.tipo == DRIVER_TUYA_LOCAL) ? TUYA_CMD_PORT : dev.httpPort;
    if (probeTcp(dev.ip, port)) {
        dev.lastSeenMs = millis();
        dev.consecutiveFails = 0;
        return true;
    }

    Serial.printf("[IOT] ⚠️ %s não respondeu em %s:%u — tentando localizar novo IP...\n",
                  dev.name, dev.ip, port);

    if (dev.tipo == DRIVER_TUYA_LOCAL) {
        scanNetworkForIotDevices(IOT_SCAN_DEFAULT_WINDOW_MS);
        // dev.ip pode ter sido atualizado dentro do scan (mesmo objeto na tabela)
        if (probeTcp(dev.ip, TUYA_CMD_PORT)) {
            dev.lastSeenMs = millis();
            dev.consecutiveFails = 0;
            return true;
        }
    }

    dev.consecutiveFails++;
    Serial.printf("[IOT] ❌ %s permanece inalcançável (%u falha(s) seguida(s))\n",
                  dev.name, dev.consecutiveFails);
    return false;
}

// =====================================================
// 🔥 DRIVER: TUYA LOCAL (protocolo LAN v3.3)
// Formato de pacote:
//   [4B header 0x000055AA][4B seq][4B command][4B payload_len]
//   [payload criptografado][4B CRC32][4B suffix 0x0000AA55]
// Payload (antes de criptografar), para CONTROL (cmd 0x07) em v3.3:
//   "3.3" + 12 bytes zero + JSON{devId,uid,t,dps}
// =====================================================

static bool tuyaSendRawOnce(IotDevice& dev, uint32_t command, JsonDocument& payloadDoc) {
    String jsonStr;
    serializeJson(payloadDoc, jsonStr);

    static uint8_t plain[512];
    size_t plainLen = 0;
    size_t headerLen = (dev.tuyaVersion == 33 && command == 0x07) ? 15 : 0;

    if (headerLen + jsonStr.length() > sizeof(plain)) {
        Serial.println("[TUYA] ❌ Payload JSON grande demais");
        return false;
    }

    if (headerLen > 0) {
        memcpy(plain, "3.3", 3);
        memset(plain + 3, 0, 12);
        memcpy(plain + 15, jsonStr.c_str(), jsonStr.length());
        plainLen = 15 + jsonStr.length();
    } else {
        memcpy(plain, jsonStr.c_str(), jsonStr.length());
        plainLen = jsonStr.length();
    }

    static uint8_t encrypted[512];
    size_t encLen = tuyaAesEncrypt((const uint8_t*)dev.localKey, plain, plainLen, encrypted, sizeof(encrypted));
    if (encLen == 0) return false;

    static uint32_t seq = 0;
    seq++;

    static uint8_t packet[600];
    if (encLen + 32 > sizeof(packet)) {
        Serial.println("[TUYA] ❌ Pacote final excede o buffer");
        return false;
    }
    size_t idx = 0;
    auto putU32 = [&](uint32_t v) {
        packet[idx++] = (v >> 24) & 0xFF; packet[idx++] = (v >> 16) & 0xFF;
        packet[idx++] = (v >> 8) & 0xFF;  packet[idx++] = v & 0xFF;
    };

    putU32(0x000055AA);
    putU32(seq);
    putU32(command);
    putU32((uint32_t)(encLen + 8));
    memcpy(packet + idx, encrypted, encLen); idx += encLen;
    uint32_t crc = tuyaCRC32(packet, idx);
    putU32(crc);
    putU32(0x0000AA55);

    WiFiClient client;
    client.setTimeout(3000);
    if (!client.connect(dev.ip, TUYA_CMD_PORT)) {
        Serial.printf("[TUYA] ❌ Falha ao conectar em %s:%d\n", dev.ip, TUYA_CMD_PORT);
        return false;
    }
    client.write(packet, idx);

    unsigned long start = millis();
    while (client.available() == 0 && millis() - start < 3000) delay(10);
    uint8_t respBuf[256];
    size_t respLen = client.available() ? client.readBytes(respBuf, sizeof(respBuf)) : 0;
    client.stop();

    Serial.printf("[TUYA] 📤 %s → cmd=0x%02X (%d bytes de resposta)\n", dev.name, command, (int)respLen);
    return respLen > 0;
}

// Envia um comando com checagem de alcançabilidade + retry/backoff.
static bool tuyaSendRaw(IotDevice& dev, uint32_t command, JsonDocument& payloadDoc) {
    if (!ensureDeviceReachable(dev)) return false;

    for (int attempt = 1; attempt <= IOT_SEND_MAX_RETRIES; attempt++) {
        if (tuyaSendRawOnce(dev, command, payloadDoc)) {
            dev.lastSeenMs = millis();
            dev.consecutiveFails = 0;
            return true;
        }
        if (attempt < IOT_SEND_MAX_RETRIES) {
            Serial.printf("[TUYA] 🔁 Tentativa %d falhou, tentando novamente...\n", attempt);
            delay(IOT_SEND_RETRY_DELAY_MS);
        }
    }
    dev.consecutiveFails++;
    return false;
}

// Liga/desliga (assume DP 1 = "switch_led" / "switch_1", padrão Tuya para a maioria
// das lâmpadas e tomadas — se o dispositivo usar outro DP, ajuste no registro)
bool tuyaSetSwitch(IotDevice& dev, bool on, int dpId = 1) {
    JsonDocument doc;
    doc["devId"] = dev.devId;
    doc["uid"]   = "";
    doc["t"]     = String((uint32_t)time(nullptr));
    JsonObject dps = doc["dps"].to<JsonObject>();
    dps[String(dpId)] = on;
    return tuyaSendRaw(dev, 0x07, doc);
}

bool tuyaSetValue(IotDevice& dev, int dpId, JsonVariant value) {
    JsonDocument doc;
    doc["devId"] = dev.devId;
    doc["uid"]   = "";
    doc["t"]     = String((uint32_t)time(nullptr));
    JsonObject dps = doc["dps"].to<JsonObject>();
    dps[String(dpId)] = value;
    return tuyaSendRaw(dev, 0x07, doc);
}

// =====================================================
// DRIVER: HTTP GENÉRICO (Tasmota / Shelly / ESPHome)
// =====================================================

static bool httpSendCommandOnce(IotDevice& dev, bool on) {
    HTTPClient http;
    String url = "http://" + String(dev.ip) + ":" + String(dev.httpPort) +
                 (on ? String(dev.httpOnPath) : String(dev.httpOffPath));
    http.begin(url);
    http.setTimeout(3000);
    int code = http.GET();
    http.end();
    Serial.printf("[HTTP] 📤 %s → %s (HTTP %d)\n", dev.name, url.c_str(), code);
    return code > 0 && code < 400;
}

bool httpSendCommand(IotDevice& dev, bool on) {
    if (!ensureDeviceReachable(dev)) return false;

    for (int attempt = 1; attempt <= IOT_SEND_MAX_RETRIES; attempt++) {
        if (httpSendCommandOnce(dev, on)) {
            dev.lastSeenMs = millis();
            dev.consecutiveFails = 0;
            return true;
        }
        if (attempt < IOT_SEND_MAX_RETRIES) {
            Serial.printf("[HTTP] 🔁 Tentativa %d falhou, tentando novamente...\n", attempt);
            delay(IOT_SEND_RETRY_DELAY_MS);
        }
    }
    dev.consecutiveFails++;
    return false;
}

// =====================================================
// DISPATCH ÚNICO — ponto de entrada usado pelo resto do gateway
// comando: "on" | "off" | "set_value" (com payload {"dp":N,"value":X})
// =====================================================

bool dispatchIotCommand(const char* deviceName, const char* comando, JsonObject payload, String& msgOut) {
    IotDevice* dev = findIotDeviceByName(deviceName);
    if (!dev) { msgOut = "Dispositivo não encontrado: " + String(deviceName); return false; }

    bool ok = false;
    if (strcmp(comando, "on") == 0 || strcmp(comando, "off") == 0) {
        bool on = strcmp(comando, "on") == 0;
        switch (dev->tipo) {
            case DRIVER_TUYA_LOCAL:   ok = tuyaSetSwitch(*dev, on); break;
            case DRIVER_HTTP_GENERIC: ok = httpSendCommand(*dev, on); break;
            default: msgOut = "Driver não configurado para " + String(deviceName); return false;
        }
    } else if (strcmp(comando, "set_value") == 0 && dev->tipo == DRIVER_TUYA_LOCAL) {
        int dp = payload["dp"] | 1;
        ok = tuyaSetValue(*dev, dp, payload["value"]);
    } else {
        msgOut = "Comando não suportado: " + String(comando);
        return false;
    }

    if (ok) {
        msgOut = "Comando enviado com sucesso";
    } else if (dev->consecutiveFails >= 3) {
        msgOut = "Dispositivo offline há " + String(dev->consecutiveFails) +
                 " tentativas — verifique alimentação/rede (último IP conhecido: " + String(dev->ip) + ")";
    } else {
        msgOut = "Falha ao enviar comando (dispositivo offline?)";
    }
    return ok;
}

// =====================================================
// UTILITÁRIO — status de todos os dispositivos (para dashboard/API)
// =====================================================

void printIotDevicesStatus() {
    Serial.println("[IOT] ── Status dos dispositivos ──");
    for (uint8_t i = 0; i < iotDeviceCount; i++) {
        if (!iotDevices[i].valid) continue;
        IotDevice& d = iotDevices[i];
        unsigned long secsAgo = d.lastSeenMs ? (millis() - d.lastSeenMs) / 1000 : 0;
        Serial.printf("  • %-16s ip=%-15s tipo=%d falhas=%u ultimo_ok=%lus atras\n",
                      d.name, d.ip, (int)d.tipo, d.consecutiveFails, secsAgo);
    }
}
