#pragma once
// network_scanner.h
// Varre a rede local (mesma sub-rede da ESP32-S3) procurando hosts ativos.
// Usa ping ICMP (componente esp_ping do IDF) + probe TCP na porta 6668
// (porta de controle local da Tuya) pra já sinalizar candidatos Tuya.
//
// Uso:
//   NetworkScanner::begin();
//   NetworkScanner::scan([](IPAddress ip, bool tuyaPort){
//       Serial.printf("Host ativo: %s  tuya_port=%d\n", ip.toString().c_str(), tuyaPort);
//   });

#include <WiFi.h>
#include <functional>
#include "ping/ping_sock.h"
#include "lwip/etharp.h"
#include "table.h"
#include "lwip/netif.h"
// Depende de lookupOUI() vindo de table.h — inclua table.h ANTES deste
// header no main.cpp (mesma ordem que device_classifier.h já exige).

namespace NetworkScanner {

struct LanHostInfo {
    IPAddress ip;
    char      mac[18];     // "" se não resolveu (ainda não está na ARP cache)
    char      vendor[28];  // "" se MAC não resolvido ou OUI desconhecido
    bool      tuyaPortOpen;
};

using HostFoundCb = std::function<void(const LanHostInfo& info)>;

// Tenta achar o MAC de um IP já na cache ARP do lwIP (populada pelo ping
// que acabou de rodar). Retorna false se ainda não estiver na cache —
// nesse caso, tenta de novo logo após o ping, a cache é preenchida quase
// que imediatamente após a resposta ICMP chegar.
inline bool resolveMacFromArp(IPAddress ip, char* macOut, size_t macOutLen) {
    ip4_addr_t target;
    target.addr = static_cast<uint32_t>(ip);

    for (struct netif* n = netif_list; n != nullptr; n = n->next) {
        struct eth_addr* ethRet = nullptr;
        const ip4_addr_t* ipRet = nullptr;
        if (etharp_find_addr(n, &target, &ethRet, &ipRet) >= 0 && ethRet) {
            snprintf(macOut, macOutLen, "%02X:%02X:%02X:%02X:%02X:%02X",
                     ethRet->addr[0], ethRet->addr[1], ethRet->addr[2],
                     ethRet->addr[3], ethRet->addr[4], ethRet->addr[5]);
            return true;
        }
    }
    return false;
}

inline bool probeTcpPort(IPAddress ip, uint16_t port, uint32_t timeoutMs = 150) {
    WiFiClient client;
    client.setTimeout(timeoutMs);
    bool ok = client.connect(ip, port, timeoutMs);
    if (ok) client.stop();
    return ok;
}

// Pinga um único host, bloqueante, com timeout curto. Retorna true se respondeu.
inline bool pingHost(IPAddress ip, uint32_t timeoutMs = 200) {
    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    ip_addr_t target;
    target.type = IPADDR_TYPE_V4;
    target.u_addr.ip4.addr = static_cast<uint32_t>(ip);
    config.target_addr = target;
    config.count = 1;
    config.timeout_ms = timeoutMs;
    config.interval_ms = 0;

    volatile bool gotReply = false;
    esp_ping_callbacks_t cbs{};
    cbs.cb_args = (void*)&gotReply;
    cbs.on_ping_success = [](esp_ping_handle_t hdl, void* args) {
        *reinterpret_cast<volatile bool*>(args) = true;
    };

    esp_ping_handle_t session;
    if (esp_ping_new_session(&config, &cbs, &session) != ESP_OK) return false;
    esp_ping_start(session);

    uint32_t start = millis();
    while (millis() - start < timeoutMs + 100) {
        if (gotReply) break;
        delay(10);
    }
    esp_ping_stop(session);
    esp_ping_delete_session(session);
    return gotReply;
}

inline void begin() {
    // esp_ping não precisa de init explícito além do WiFi já estar conectado.
}

// Varre host.1 até host.254 da sub-rede atual. Bloqueante — rode em task/core
// separado se não quiser travar o loop principal.
inline void scan(HostFoundCb onFound, uint8_t startHost = 1, uint8_t endHost = 254) {
    IPAddress localIp = WiFi.localIP();

    if (localIp == IPAddress(0, 0, 0, 0)) {
        Serial.println("[scanner] WiFi não conectado, abortando scan.");
        return;
    }

    // Assume /24 (mais comum em redes domésticas). Para outras máscaras,
    // ajuste o range calculando base/broadcast a partir de WiFi.subnetMask().
    IPAddress base(localIp[0], localIp[1], localIp[2], 0);

    for (uint16_t h = startHost; h <= endHost; h++) {
        IPAddress candidate(base[0], base[1], base[2], (uint8_t)h);
        if (candidate == localIp) continue;

        if (pingHost(candidate)) {
            LanHostInfo info;
            info.ip = candidate;
            info.mac[0] = '\0';
            info.vendor[0] = '\0';
            info.tuyaPortOpen = probeTcpPort(candidate, 6668);

            // A cache ARP costuma já ter a entrada logo após a resposta de
            // ping; se não tiver na primeira tentativa, espera um instante
            // curto e tenta de novo antes de desistir.
            if (!resolveMacFromArp(candidate, info.mac, sizeof(info.mac))) {
                delay(20);
                resolveMacFromArp(candidate, info.mac, sizeof(info.mac));
            }

            if (info.mac[0] != '\0') {
                char ouiTipo[48] = "N/A"; // não usado aqui, só o vendor interessa
                lookupOUI(info.mac, info.vendor, sizeof(info.vendor), ouiTipo, sizeof(ouiTipo));
            }

            onFound(info);
        }
        yield(); // não travar o watchdog
    }
}

} // namespace NetworkScanner
