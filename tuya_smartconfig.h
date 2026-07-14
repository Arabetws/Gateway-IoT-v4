/*
 * tuya_smartconfig.h
 *
 * Port C++/ESP32 do protocolo Tuya SmartConfig (EZ-mode / "Tuya Link").
 *
 * Baseado em engenharia reversa publicada em:
 *   - ct-Open-Source/tuya-convert (scripts/smartconfig/{smartconfig,broadcast,multicast,crc}.py)
 *     https://github.com/ct-Open-Source/tuya-convert  (GPL-3.0)
 *     estratégia de broadcast originalmente portada de https://github.com/tuyapi/link
 *     estratégia de multicast: engenharia reversa por kueblc
 *   - elttam.com/blog/ez-mode-pairing (validação da codificação por tamanho de pacote)
 *
 * Este módulo reimplementa, byte a byte, a mesma lógica do Python original,
 * adaptada para sockets BSD do lwIP (ESP-IDF / Arduino-ESP32).
 *
 * PRÉ-REQUISITO: o ESP32 já deve estar conectado (modo STA) à MESMA rede WiFi
 * 2.4GHz que você quer entregar para a lâmpada — é essa rede que será
 * anunciada por broadcast/multicast local. A lâmpada não precisa estar
 * associada a nada ainda: ela escuta em modo promíscuo, no canal em que o
 * ESP32 está transmitindo, e decodifica a sequência de tamanhos de pacote.
 *
 * Uso típico dentro do seu pairing_provider.h:
 *
 *   #include "tuya_smartconfig.h"
 *   TuyaSmartConfig::begin();
 *   TuyaSmartConfig::run("minhaSenhaWifi", "MeuSSID", "BR", "00000000", "0101", 10);
 *   TuyaSmartConfig::end();
 *
 * region/token/secret: como a lâmpada já está vinculada à sua conta Tuya
 * (não é um flash tipo tuya-convert), token e secret podem ficar com os
 * valores dummy usados pelo próprio projeto original ("00000000" / "0101").
 * region é só um prefixo de 2 letras (ex: "US", "EU", "CN") sem função de
 * validação real no protocolo local.
 */

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <vector>
#include <string>
#include "mbedtls/aes.h"
#include "esp_task_wdt.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace TuyaSmartConfig {

// ---------------------------------------------------------------------
// CRC8 e CRC32 (crc.py)
// ---------------------------------------------------------------------

inline uint8_t crc8_byte(uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if ((r ^ b) & 1) {
            r ^= 0x18;
            r >>= 1;
            r |= 0x80;
        } else {
            r >>= 1;
        }
        b >>= 1;
    }
    return r;
}

// crc_8(a): r = 0; for b in a: r = crc_8_byte(r ^ b)
inline uint8_t crc8(const std::vector<uint8_t>& a) {
    uint8_t r = 0;
    for (uint8_t b : a) {
        r = crc8_byte((uint8_t)(r ^ b));
    }
    return r;
}

// CRC32 padrão (IEEE 802.3 / zlib) — é exatamente o que crc.py implementa
// (init 0xFFFFFFFF, poly refletido 0xEDB88320, xorout 0xFFFFFFFF).
inline uint32_t crc32_std(const uint8_t* data, size_t len) {
    uint32_t r = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        r ^= data[i];
        for (int k = 0; k < 8; k++) {
            r = (r & 1) ? (r >> 1) ^ 0xEDB88320u : (r >> 1);
        }
    }
    return r ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------
// AES-128-ECB com chave fixa do protocolo (multicast.py)
// chave: "a3c6794oiu876t54" (16 bytes ASCII), padding com \0 até múltiplo de 16
// ---------------------------------------------------------------------

inline std::vector<uint8_t> aes_ecb_encrypt(const std::string& plain) {
    static const uint8_t key[16] = {
        0xa3, 0xc6, 0x79, 0x4f, 0x69, 0x75, 0x38, 0x37,
        0x36, 0x74, 0x35, 0x34, 0x00, 0x00, 0x00, 0x00
    };

    size_t padded_len = ((plain.size() + 15) / 16) * 16;
    if (padded_len == 0) padded_len = 16; // pad(data,16) de string vazia -> ainda 1 bloco
    std::vector<uint8_t> buf(padded_len, 0);
    memcpy(buf.data(), plain.data(), plain.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    std::vector<uint8_t> out(padded_len);
    for (size_t off = 0; off < padded_len; off += 16) {
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, buf.data() + off, out.data() + off);
    }
    mbedtls_aes_free(&ctx);
    return out;
}

// ---------------------------------------------------------------------
// broadcast.py — encode_broadcast_body
// ---------------------------------------------------------------------

// broadcast_head = [1, 3, 6, 10]  (tamanhos de pacote, cabeçalho fixo)
inline std::vector<int> broadcast_head() { return {1, 3, 6, 10}; }

inline std::vector<int> encode_broadcast_body(const std::string& password,
                                               const std::string& ssid,
                                               const std::string& token_group) {
    std::vector<uint8_t> r;
    r.push_back((uint8_t)password.size());
    for (char c : password) r.push_back((uint8_t)c);
    r.push_back((uint8_t)token_group.size());
    for (char c : token_group) r.push_back((uint8_t)c);
    for (char c : ssid) r.push_back((uint8_t)c);

    std::vector<int> e;
    int length = (int)r.size();
    uint8_t length_crc = crc8({(uint8_t)length});

    e.push_back((length >> 4) | 16);
    e.push_back((length & 0xF) | 32);
    e.push_back((length_crc >> 4) | 48);
    e.push_back((length_crc & 0xF) | 64);

    // Em Python, "for i in range(0, length, 4)" deixa a variável i com o
    // valor do ÚLTIMO i usado no corpo do loop (não o valor que causaria a
    // saída). Replicamos isso com last_i abaixo para casar exatamente com
    // o "e.extend([256] * (length - i))" que vem depois do loop original.
    int sequence = 0;
    int last_i = 0;
    for (int i = 0; i < length; i += 4) {
        last_i = i;
        std::vector<uint8_t> group;
        group.push_back((uint8_t)sequence);
        int chunk = std::min(4, length - i);
        for (int k = 0; k < chunk; k++) group.push_back(r[i + k]);
        while (group.size() < 5) group.push_back(0);

        uint8_t group_crc = crc8(group);
        e.push_back((group_crc & 0x7F) | 128);
        e.push_back(sequence | 128);
        for (int k = 0; k < chunk; k++) e.push_back(r[i + k] | 256);

        sequence++;
    }
    // réplica fiel de "e.extend([256] * (length - i))" (i = last_i aqui)
    for (int pad = 0; pad < (length - last_i); pad++) e.push_back(256);

    return e;
}

// ---------------------------------------------------------------------
// multicast.py — encode_pw / encode_plain / bytes_to_ips
// ---------------------------------------------------------------------

inline std::vector<uint8_t> encode_pw(const std::string& pw) {
    std::vector<uint8_t> pw_bytes(pw.begin(), pw.end());
    std::vector<uint8_t> encrypted_pw = aes_ecb_encrypt(pw);
    uint32_t crc = crc32_std(pw_bytes.data(), pw_bytes.size());

    std::vector<uint8_t> r;
    r.push_back((uint8_t)pw.size());
    r.push_back((uint8_t)pw.size());
    for (int i = 0; i < 32; i += 8) r.push_back((crc >> i) & 0xFF);
    r.insert(r.end(), encrypted_pw.begin(), encrypted_pw.end());
    return r;
}

inline std::vector<uint8_t> encode_plain(const std::string& s) {
    std::vector<uint8_t> s_bytes(s.begin(), s.end());
    uint32_t crc = crc32_std(s_bytes.data(), s_bytes.size());

    std::vector<uint8_t> r;
    r.push_back((uint8_t)s.size());
    r.push_back((uint8_t)s.size());
    for (int i = 0; i < 32; i += 8) r.push_back((crc >> i) & 0xFF);
    r.insert(r.end(), s_bytes.begin(), s_bytes.end());
    return r;
}

inline std::vector<std::string> bytes_to_ips(std::vector<uint8_t> data, int sequence) {
    std::vector<std::string> r;
    if (data.size() & 1) data.push_back(0);
    for (size_t i = 0; i < data.size(); i += 2) {
        char ip[24];
        snprintf(ip, sizeof(ip), "226.%d.%d.%d", sequence, data[i + 1], data[i]);
        r.push_back(std::string(ip));
        sequence++;
    }
    return r;
}

inline std::vector<std::string> multicast_head() {
    std::string tag = "TYST01";
    std::vector<uint8_t> bytes(tag.begin(), tag.end());
    return bytes_to_ips(bytes, 120);
}

inline std::vector<std::string> encode_multicast_body(const std::string& password,
                                                        const std::string& ssid,
                                                        const std::string& token_group) {
    std::vector<std::string> r;
    auto ssid_encoded = encode_plain(ssid);
    auto part1 = bytes_to_ips(ssid_encoded, 64);
    r.insert(r.end(), part1.begin(), part1.end());

    auto password_encoded = encode_pw(password);
    auto part2 = bytes_to_ips(password_encoded, 0);
    r.insert(r.end(), part2.begin(), part2.end());

    auto token_group_encoded = encode_plain(token_group);
    auto part3 = bytes_to_ips(token_group_encoded, 32);
    r.insert(r.end(), part3.begin(), part3.end());

    return r;
}

// ---------------------------------------------------------------------
// Socket bruto (equivalente a SmartConfigSocket em smartconfig.py)
// ---------------------------------------------------------------------

class SmartConfigSocket {
public:
    static constexpr uint32_t GAP_US = 5000; // 5ms, igual ao GAP do Python

    SmartConfigSocket() {
        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int opt_reuse = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(opt_reuse));
        int opt_bcast = 1;
        setsockopt(sock_, SOL_SOCKET, SO_BROADCAST, &opt_bcast, sizeof(opt_bcast));
        uint8_t ttl = 1;
        setsockopt(sock_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

        // Bind no IP local do ESP32 (equivalente ao BIND_ADDRESS do script original,
        // que lá era o IP da própria interface que fazia o papel de AP/gateway)
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = 0; // porta efêmera, como no Python (bind com porta 0)
        local_addr.sin_addr.s_addr = (uint32_t)WiFi.localIP();
        bind(sock_, (struct sockaddr*)&local_addr, sizeof(local_addr));
    }

    ~SmartConfigSocket() {
        if (sock_ >= 0) close(sock_);
    }

    // send_broadcast: cada "length" vira o TAMANHO do pacote UDP (payload de zeros)
    void send_broadcast(const std::vector<int>& lengths) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(30011);
        dest.sin_addr.s_addr = htonl(INADDR_BROADCAST); // 255.255.255.255

        static std::vector<uint8_t> zeros;
        for (int len : lengths) {
            if ((int)zeros.size() < len) zeros.resize(len, 0);
            sendto(sock_, zeros.data(), len, 0, (struct sockaddr*)&dest, sizeof(dest));
            esp_task_wdt_reset(); // sem isso, ~7s por tentativa estoura o TWDT do loopTask
            delayMicroseconds(GAP_US);
        }
    }

    // send_multicast: cada IP da lista vira o DESTINO de um pacote de 1 byte
    void send_multicast(const std::vector<std::string>& ips) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(30012);

        uint8_t payload = 0;
        for (const auto& ip : ips) {
            dest.sin_addr.s_addr = inet_addr(ip.c_str());
            sendto(sock_, &payload, 1, 0, (struct sockaddr*)&dest, sizeof(dest));
            esp_task_wdt_reset();
            delayMicroseconds(GAP_US);
        }
    }

private:
    int sock_ = -1;
};

// ---------------------------------------------------------------------
// smartconfig() — orquestra tudo, igual smartconfig.py
// ---------------------------------------------------------------------

inline void smartconfig_once(const std::string& password, const std::string& ssid,
                              const std::string& region, const std::string& token,
                              const std::string& secret) {
    SmartConfigSocket sock;

    std::string token_group = region + token + secret;
    auto b_body = encode_broadcast_body(password, ssid, token_group);
    auto m_body = encode_multicast_body(password, ssid, token_group);
    auto m_head = multicast_head();
    auto b_head = broadcast_head();

    // cabeçalho repetido (40x no original, valor já reduzido pelo próprio autor)
    for (int i = 0; i < 40; i++) {
        sock.send_multicast(m_head);
        sock.send_broadcast(b_head);
        esp_task_wdt_reset();
    }

    // corpo com dados reais (10x no original)
    for (int i = 0; i < 10; i++) {
        sock.send_multicast(m_head);
        sock.send_multicast(m_body);
        sock.send_broadcast(b_body);
        esp_task_wdt_reset();
        Serial.print('.');
    }
}

// begin(): opcional, aqui só documenta que WiFi.begin() já deve ter sido
// chamado e a conexão STA já deve estar ESTABELECIDA antes de rodar isso.
inline bool begin() {
    return WiFi.status() == WL_CONNECTED;
}

// run(): chama smartconfig_once várias vezes com pausa entre tentativas,
// igual ao loop do main.py original.
inline void run(const std::string& password, const std::string& ssid,
                 const std::string& region = "BR", const std::string& token = "00000000",
                 const std::string& secret = "0101", int attempts = 10) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[TuyaSmartConfig] ERRO: ESP32 precisa estar conectado via WiFi.begin() antes de chamar run()");
        return;
    }

    Serial.printf("[TuyaSmartConfig] Colocando a lampada em modo EZ-config (LED piscando rapido)\n");
    Serial.printf("[TuyaSmartConfig] SSID: %s\n", ssid.c_str());

    for (int i = 0; i < attempts; i++) {
        esp_task_wdt_reset();
        smartconfig_once(password, ssid, region, token, secret);
        Serial.println();
        Serial.printf("[TuyaSmartConfig] Tentativa %d/%d concluida\n", i + 1, attempts);
        delay(1000);
    }
}

inline void end() {
    // nada persistente a liberar; cada SmartConfigSocket já fecha o próprio fd
}

} // namespace TuyaSmartConfig
