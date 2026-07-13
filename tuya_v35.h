// =====================================================
// tuya_v35.h — Suporte a Tuya Local Protocol v3.5
// ─────────────────────────────────────────────────
// [FIX v4] Corrigido com base em captura REAL (set_debug)
// de um handshake + query bem-sucedidos contra o device de
// produção (log fornecido pelo usuário, decodificado byte a
// byte). Dois bugs confirmados na versão anterior:
//
//   BUG 1 — IV fixo só era usado no handshake. Na captura
//   real, TODO frame enviado pelo cliente (START, FINISH, e
//   também comandos pós-handshake como DP_QUERY/CONTROL) usa
//   o mesmo IV fixo de 12 bytes = ASCII "0123456789ab".
//   Confirmado em dois pontos do log: "payload [2] encrypted"
//   (handshake) e "payload [4] encrypted" (query pós-handshake,
//   já usando a session key) — ambos com os mesmos 12 bytes
//   30 31 32 33 34 35 36 37 38 39 61 62 logo após o header.
//
//   BUG 2 — o retcode de 4 bytes NÃO é um campo separado no
//   frame antes do IV. Ele faz parte do PLAINTEXT decifrado:
//   plaintext = retcode(4) + payload_real. Confirmado pelo RESP
//   real: length=0x50(80) => ciphertext=80-12-16=52 bytes: o log
//   mostra "decrypted session key negotiation step 2 payload=...
//   len = 48" após já ter descartado 4 bytes de retcode do início
//   dos 52 bytes decifrados. A versão anterior pulava 4 bytes
//   ANTES de procurar o IV no frame recebido — o que desalinhava
//   IV/ciphertext/Tag em 4 bytes e quebrava a autenticação GCM
//   toda vez que uma resposta chegava.
//
// Requer: mbedtls/gcm.h, mbedtls/md.h (disponíveis no
// framework Arduino-ESP32 / esp-idf).
// =====================================================

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <ArduinoJson.h>

// =====================================================
// CONSTANTES DE PROTOCOLO
// =====================================================

#define TUYA_CMD_SESS_KEY_NEG_START   0x03
#define TUYA_CMD_SESS_KEY_NEG_RESP    0x04
#define TUYA_CMD_SESS_KEY_NEG_FINISH  0x05
#define TUYA_CMD_DP_QUERY_NEW         0x10
#define TUYA_CMD_CONTROL_NEW          0x0D

#define TUYA_V35_CONNECT_TIMEOUT_MS   3000
#define TUYA_V35_IO_TIMEOUT_MS        3000

// [FIX v4] IV fixo usado em TODO frame enviado pelo cliente
// (handshake E comandos pós-handshake) — confirmado por captura real.
static const uint8_t TUYA_CLIENT_FIXED_IV[12] = {
    '0','1','2','3','4','5','6','7','8','9','a','b'
};

// =====================================================
// ESTADO DE SESSÃO (por dispositivo, não persistido)
// =====================================================

struct TuyaSessionV35 {
    uint8_t  sessionKey[16];
    bool     valid = false;
    uint32_t seq   = 1;
};

// =====================================================
// HELPERS CRIPTOGRÁFICOS
// =====================================================

static void tuyaHmacSha256(const uint8_t* key, size_t keyLen,
                            const uint8_t* msg, size_t msgLen,
                            uint8_t* out32)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    mbedtls_md_hmac_update(&ctx, msg, msgLen);
    mbedtls_md_hmac_finish(&ctx, out32);
    mbedtls_md_free(&ctx);
}

static bool tuyaGcmEncrypt(const uint8_t* key16, const uint8_t* iv12,
                            const uint8_t* aad, size_t aadLen,
                            const uint8_t* input, size_t inLen,
                            uint8_t* output, uint8_t* tag16)
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key16, 128) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, inLen,
                                         iv12, 12, aad, aadLen,
                                         input, output, 16, tag16);
    mbedtls_gcm_free(&gcm);
    return ret == 0;
}

static bool tuyaGcmDecrypt(const uint8_t* key16, const uint8_t* iv12,
                            const uint8_t* aad, size_t aadLen,
                            const uint8_t* input, size_t inLen,
                            const uint8_t* tag16,
                            uint8_t* output)
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key16, 128) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    int ret = mbedtls_gcm_auth_decrypt(&gcm, inLen, iv12, 12, aad, aadLen,
                                        tag16, 16, input, output);
    mbedtls_gcm_free(&gcm);
    return ret == 0; // ret != 0 quando a Tag não bate
}

// =====================================================
// FRAME 6699 GENÉRICO
// Layout no fio (confirmado por captura real):
//   00006699 | reserved(2) | seq(4) | cmd(4) | len(4) |
//   IV(12) | ciphertext(len-28) | Tag(16) | 00009966
// AAD = reserved(2)+seq(4)+cmd(4)+len(4) = 14 bytes
// O retcode (quando presente) é parte do PLAINTEXT decifrado,
// não um campo do frame — ele vem nos primeiros 4 bytes do
// resultado da decriptação, em respostas device->client.
// =====================================================

static bool tuyaSend6699Frame(WiFiClient& client, const uint8_t* key16,
                               const uint8_t* iv12, // sempre TUYA_CLIENT_FIXED_IV na prática
                               uint32_t seq, uint32_t cmd,
                               const uint8_t* plain, size_t plainLen)
{
    if (plainLen > 400) {
        Serial.println("[TUYA35] ❌ Payload grande demais para o buffer");
        return false;
    }

    uint16_t reserved = 0x0000;
    uint32_t length = (uint32_t)(12 + plainLen + 16);

    uint8_t aad[14];
    aad[0] = (reserved >> 8) & 0xFF; aad[1] = reserved & 0xFF;
    aad[2] = (seq >> 24) & 0xFF; aad[3] = (seq >> 16) & 0xFF;
    aad[4] = (seq >> 8) & 0xFF;  aad[5] = seq & 0xFF;
    aad[6] = (cmd >> 24) & 0xFF; aad[7] = (cmd >> 16) & 0xFF;
    aad[8] = (cmd >> 8) & 0xFF;  aad[9] = cmd & 0xFF;
    aad[10] = (length >> 24) & 0xFF; aad[11] = (length >> 16) & 0xFF;
    aad[12] = (length >> 8) & 0xFF;  aad[13] = length & 0xFF;

    static uint8_t ciphertext[400];
    uint8_t tag[16];
    if (!tuyaGcmEncrypt(key16, iv12, aad, sizeof(aad), plain, plainLen, ciphertext, tag)) {
        Serial.println("[TUYA35] ❌ Falha ao criptografar frame 6699 (GCM)");
        return false;
    }

    static uint8_t frame[18 + 12 + 400 + 16 + 4];
    size_t idx = 0;
    auto putU32 = [&](uint32_t v) {
        frame[idx++] = (v >> 24) & 0xFF; frame[idx++] = (v >> 16) & 0xFF;
        frame[idx++] = (v >> 8) & 0xFF;  frame[idx++] = v & 0xFF;
    };
    frame[idx++] = 0x00; frame[idx++] = 0x00; frame[idx++] = 0x66; frame[idx++] = 0x99;
    frame[idx++] = (reserved >> 8) & 0xFF; frame[idx++] = reserved & 0xFF;
    putU32(seq);
    putU32(cmd);
    putU32(length);
    memcpy(frame + idx, iv12, 12); idx += 12;
    memcpy(frame + idx, ciphertext, plainLen); idx += plainLen;
    memcpy(frame + idx, tag, 16); idx += 16;
    frame[idx++] = 0x00; frame[idx++] = 0x00; frame[idx++] = 0x99; frame[idx++] = 0x66;

    return client.write(frame, idx) == idx;
}

// hasRetcode = true para qualquer resposta device->client.
// [FIX v4] O retcode é extraído do PLAINTEXT após decifrar,
// não é mais tratado como campo cru antes do IV.
static bool tuyaRecv6699Frame(WiFiClient& client, const uint8_t* key16,
                               bool hasRetcode,
                               uint8_t* outPlain, size_t outCapacity, size_t* outLen,
                               uint32_t* outCmd = nullptr,
                               int32_t* outRetcode = nullptr,
                               uint32_t timeoutMs = TUYA_V35_IO_TIMEOUT_MS)
{
    unsigned long start = millis();
    uint8_t header[18]; // prefix(4)+reserved(2)+seq(4)+cmd(4)+len(4)
    size_t got = 0;
    while (got < 18 && millis() - start < timeoutMs) {
        if (client.available()) {
            int n = client.read(header + got, 18 - got);
            if (n > 0) got += n;
        } else delay(5);
    }
    if (got < 18) {
        Serial.println("[TUYA35] ❌ Timeout aguardando header 6699");
        return false;
    }

    uint32_t prefix = ((uint32_t)header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
    if (prefix != 0x00006699) {
        Serial.printf("[TUYA35] ❌ Prefixo inesperado: %08X\n", (unsigned)prefix);
        return false;
    }

    uint32_t cmd = ((uint32_t)header[10] << 24) | (header[11] << 16) | (header[12] << 8) | header[13];
    uint32_t length = ((uint32_t)header[14] << 24) | (header[15] << 16) | (header[16] << 8) | header[17];
    // length cobre SÓ IV+ciphertext+Tag (sem retcode — ele está dentro do ciphertext)
    if (length < 28 || length > 600) return false;

    static uint8_t body[600];
    got = 0;
    start = millis();
    while (got < length && millis() - start < timeoutMs) {
        if (client.available()) {
            int n = client.read(body + got, length - got);
            if (n > 0) got += n;
        } else delay(5);
    }
    if (got < length) {
        Serial.println("[TUYA35] ❌ Timeout aguardando corpo do frame 6699");
        return false;
    }

    // [FIX v4] IV começa IMEDIATAMENTE após o header — sem offset de retcode aqui
    const uint8_t* iv = body;
    size_t cipherLen = length - 12 - 16;
    const uint8_t* ciphertext = body + 12;
    const uint8_t* tag = body + 12 + cipherLen;

    uint8_t aad[14];
    aad[0] = header[4]; aad[1] = header[5];
    memcpy(aad + 2, header + 6, 4);
    memcpy(aad + 6, header + 10, 4);
    memcpy(aad + 10, header + 14, 4);

    static uint8_t decrypted[600];
    if (cipherLen > sizeof(decrypted)) return false;
    if (!tuyaGcmDecrypt(key16, iv, aad, sizeof(aad), ciphertext, cipherLen, tag, decrypted)) {
        Serial.println("[TUYA35] ❌ Falha ao autenticar/decriptar (Tag inválida)");
        return false;
    }

    // [FIX v4] Retcode extraído do PLAINTEXT decifrado, não do frame cru
    const uint8_t* payload = decrypted;
    size_t payloadLen = cipherLen;
    int32_t retcode = 0;
    if (hasRetcode) {
        if (cipherLen < 4) return false;
        retcode = ((int32_t)decrypted[0] << 24) | (decrypted[1] << 16) | (decrypted[2] << 8) | decrypted[3];
        payload = decrypted + 4;
        payloadLen = cipherLen - 4;
    }

    if (payloadLen > outCapacity) return false;
    memcpy(outPlain, payload, payloadLen);
    *outLen = payloadLen;
    if (outCmd) *outCmd = cmd;
    if (outRetcode) *outRetcode = retcode;
    return true;
}

// =====================================================
// HANDSHAKE — negociação da session key (v3.5)
// =====================================================

bool tuyaNegotiateSessionV35(WiFiClient& client, const uint8_t* realKey16,
                              TuyaSessionV35& sess)
{
    // 1) Gera nonce do cliente e envia START (0x03) via frame 6699,
    //    cifrado com local_key + IV FIXO
    uint8_t clientNonce[16];
    for (int i = 0; i < 16; i++) clientNonce[i] = (uint8_t)esp_random();

    if (!tuyaSend6699Frame(client, realKey16, TUYA_CLIENT_FIXED_IV, sess.seq++,
                            TUYA_CMD_SESS_KEY_NEG_START, clientNonce, 16)) {
        Serial.println("[TUYA35] ❌ Falha ao enviar START do handshake");
        return false;
    }

    // 2) Recebe RESP (0x04): device_nonce(16) + HMAC(client_nonce)(32) = 48 bytes
    //    (após o retcode de 4 bytes ser removido do plaintext decifrado)
    uint8_t respPlain[64];
    size_t respLen = 0;
    if (!tuyaRecv6699Frame(client, realKey16, true, respPlain, sizeof(respPlain), &respLen)) {
        Serial.println("[TUYA35] ❌ Timeout/erro aguardando RESP do handshake");
        return false;
    }
    if (respLen < 48) {
        Serial.printf("[TUYA35] ❌ RESP curto demais (%d bytes, esperado >=48)\n", (int)respLen);
        return false;
    }

    uint8_t deviceNonce[16];
    memcpy(deviceNonce, respPlain, 16);
    const uint8_t* recvHmac = respPlain + 16;

    // 3) Valida HMAC do client_nonce
    uint8_t expectedHmac[32];
    tuyaHmacSha256(realKey16, 16, clientNonce, 16, expectedHmac);
    if (memcmp(expectedHmac, recvHmac, 32) != 0) {
        Serial.println("[TUYA35] ❌ HMAC do RESP não confere — local_key errada");
        return false;
    }

    // 4) Envia FINISH (0x05) = HMAC-SHA256(device_nonce), mesmo esquema do START
    uint8_t finishHmac[32];
    tuyaHmacSha256(realKey16, 16, deviceNonce, 16, finishHmac);

    if (!tuyaSend6699Frame(client, realKey16, TUYA_CLIENT_FIXED_IV, sess.seq++,
                            TUYA_CMD_SESS_KEY_NEG_FINISH, finishHmac, 32)) {
        Serial.println("[TUYA35] ❌ Falha ao enviar FINISH do handshake");
        return false;
    }

    // 5) Deriva a session key:
    //    tmp = client_nonce XOR device_nonce
    //    session_key = GCM_encrypt(local_key, iv=client_nonce[:12], tmp) -> 16 bytes de ciphertext
    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = clientNonce[i] ^ deviceNonce[i];

    uint8_t gcmOut[16], gcmTag[16];
    uint8_t sessIv[12];
    memcpy(sessIv, clientNonce, 12); // IV = client_nonce[:12], explícito (não implícito)
    if (!tuyaGcmEncrypt(realKey16, sessIv, nullptr, 0, tmp, 16, gcmOut, gcmTag)) {
        Serial.println("[TUYA35] ❌ Falha ao derivar session key (GCM)");
        return false;
    }
    memcpy(sess.sessionKey, gcmOut, 16);
    sess.valid = true;

    Serial.println("[TUYA35] ✅ Session key negociada com sucesso");
    return true;
}

// =====================================================
// API DE ALTO NÍVEL — comando pós-handshake
// [FIX v4] Também usa TUYA_CLIENT_FIXED_IV, confirmado pela
// captura real ("payload [4] encrypted" no log do usuário).
// =====================================================

static TuyaSessionV35 tuyaSessions[MAX_IOT_DEVICES];

bool tuyaSetSwitchV35(IotDevice& dev, bool on, int dpId, uint8_t deviceIdx) {
    uint8_t realKey[16];
    memcpy(realKey, dev.localKey, 16);

    WiFiClient client;
    client.setTimeout(TUYA_V35_CONNECT_TIMEOUT_MS);
    if (!client.connect(dev.ip, TUYA_CMD_PORT)) {
        Serial.printf("[TUYA35] ❌ Falha ao conectar em %s:%d\n", dev.ip, TUYA_CMD_PORT);
        return false;
    }

    TuyaSessionV35& sess = tuyaSessions[deviceIdx];
    sess.valid = false;
    sess.seq = 1;

    if (!tuyaNegotiateSessionV35(client, realKey, sess)) {
        client.stop();
        return false;
    }

    JsonDocument doc;
    doc["protocol"] = 5;
    doc["t"] = (uint32_t)time(nullptr);
    JsonObject data = doc["data"].to<JsonObject>();
    data["cid"] = "";
    JsonObject dps = data["dps"].to<JsonObject>();
    dps[String(dpId)] = on;

    String jsonStr;
    serializeJson(doc, jsonStr);

    bool sent = tuyaSend6699Frame(client, sess.sessionKey, TUYA_CLIENT_FIXED_IV,
                                   sess.seq++, TUYA_CMD_CONTROL_NEW,
                                   (const uint8_t*)jsonStr.c_str(), jsonStr.length());
    if (!sent) {
        client.stop();
        return false;
    }

    uint8_t respPlain[500];
    size_t respLen = 0;
    bool gotResp = tuyaRecv6699Frame(client, sess.sessionKey, true,
                                      respPlain, sizeof(respPlain), &respLen);
    client.stop();

    if (gotResp) {
        respPlain[respLen] = '\0';
        Serial.printf("[TUYA35] 📥 Resposta: %s\n", (const char*)respPlain);
    } else {
        Serial.println("[TUYA35] ⚠️ Comando enviado mas sem confirmação de resposta");
    }

    return sent;
}
