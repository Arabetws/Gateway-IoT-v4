#pragma once
#include <Arduino.h>
#include <Preferences.h>

// =====================================================
// devices.h — IoT Platform ESP32-S3 Gateway v3.0
// ─────────────────────────────────────────────────
// Define todos os tipos de dispositivos suportados,
// seus comandos, tópicos MQTT e sistema de cache
// (equivalente ao cache de dispositivos do celular)
// =====================================================

// =====================================================
// TIPOS DE DISPOSITIVOS
// =====================================================

enum DeviceType : uint8_t {
    DEV_UNKNOWN         = 0,
    // Iluminação
    DEV_LAMP            = 1,   // Lâmpada Inteligente
    DEV_LED_STRIP       = 2,   // Fita de LED RGB
    // Controle elétrico
    DEV_SWITCH          = 3,   // Interruptor Inteligente
    DEV_OUTLET          = 4,   // Tomada Inteligente
    // Climatização
    DEV_AC              = 5,   // Ar Condicionado
    DEV_FAN             = 6,   // Ventilador
    // Entretenimento
    DEV_TV              = 7,   // Televisão
    // Sensores ambientais
    DEV_TEMP_SENSOR     = 8,   // Sensor de Temperatura
    DEV_HUMIDITY_SENSOR = 9,   // Sensor de Umidade
    DEV_SMOKE_SENSOR    = 10,  // Sensor de Fumaça
    DEV_GAS_SENSOR      = 11,  // Sensor de Gás
    // Segurança
    DEV_MOTION_SENSOR   = 12,  // Sensor de Movimento
    DEV_DOOR_SENSOR     = 13,  // Sensor de Porta/Janela
    DEV_CAMERA          = 14,  // Câmera IP
    DEV_ALARM           = 15,  // Alarme
    DEV_LOCK            = 16,  // Fechadura Inteligente
    // Gateway/Hub
    DEV_GATEWAY         = 99,  // Este próprio gateway
};

// =====================================================
// PROTOCOLOS SUPORTADOS
// =====================================================

enum DeviceProtocol : uint8_t {
    PROTO_UNKNOWN   = 0,
    PROTO_WIFI_MQTT = 1,   // WiFi + MQTT (ESP32, Tasmota, ESPHome)
    PROTO_WIFI_TUYA = 2,   // WiFi + Tuya Cloud
    PROTO_WIFI_HTTP = 3,   // WiFi + HTTP REST (Shelly)
    PROTO_BLE       = 4,   // Bluetooth LE
    PROTO_ZIGBEE    = 5,   // Zigbee (via hub)
    PROTO_ZWAVE     = 6,   // Z-Wave (via hub)
    PROTO_IR        = 7,   // Infravermelho (TV, AC, Ventilador)
    PROTO_MATTER    = 8,   // Matter/Thread
};

// =====================================================
// MARCAS SUPORTADAS POR TIPO
// =====================================================

// Mapeamento: tipo → lista de marcas comuns no mercado BR
struct BrandEntry {
    const char* marca;
    DeviceProtocol protocolo;
};

// Lâmpadas
static const BrandEntry BRANDS_LAMP[] = {
    {"Philips Hue",    PROTO_ZIGBEE},
    {"WiZ",            PROTO_WIFI_MQTT},
    {"IKEA Trådfri",   PROTO_ZIGBEE},
    {"Govee",          PROTO_WIFI_TUYA},
    {"Intelbras",      PROTO_WIFI_TUYA},
    {"Tuya Generic",   PROTO_WIFI_TUYA},
    {"Sonoff B02",     PROTO_WIFI_MQTT},
    {"Shelly Bulb",    PROTO_WIFI_HTTP},
    {"Meross",         PROTO_WIFI_TUYA},
    {"TP-Link Tapo",   PROTO_WIFI_TUYA},
    {"ESP32 Custom",   PROTO_WIFI_MQTT},
};

// Fitas LED
static const BrandEntry BRANDS_LED_STRIP[] = {
    {"WLED ESP32",     PROTO_WIFI_MQTT},
    {"Govee Strip",    PROTO_WIFI_TUYA},
    {"Tuya LED Strip", PROTO_WIFI_TUYA},
    {"Sonoff L1",      PROTO_WIFI_MQTT},
    {"ESP32 Custom",   PROTO_WIFI_MQTT},
};

// Interruptores
static const BrandEntry BRANDS_SWITCH[] = {
    {"Sonoff Basic",   PROTO_WIFI_MQTT},
    {"Sonoff Mini",    PROTO_WIFI_MQTT},
    {"Shelly 1",       PROTO_WIFI_HTTP},
    {"Tuya Switch",    PROTO_WIFI_TUYA},
    {"Intelbras EWS",  PROTO_WIFI_TUYA},
    {"ESP32 Custom",   PROTO_WIFI_MQTT},
    {"Zigbee Switch",  PROTO_ZIGBEE},
};

// Tomadas
static const BrandEntry BRANDS_OUTLET[] = {
    {"TP-Link Tapo P100", PROTO_WIFI_TUYA},
    {"Sonoff S26",     PROTO_WIFI_MQTT},
    {"Shelly Plug",    PROTO_WIFI_HTTP},
    {"Tuya Plug",      PROTO_WIFI_TUYA},
    {"Meross MSS310",  PROTO_WIFI_TUYA},
    {"Intelbras EPS",  PROTO_WIFI_TUYA},
    {"ESP32 Custom",   PROTO_WIFI_MQTT},
};

// Ar condicionado
static const BrandEntry BRANDS_AC[] = {
    {"Positivo Casa+", PROTO_WIFI_TUYA},
    {"Intelbras iR",   PROTO_IR},
    {"Broadlink RM4",  PROTO_IR},
    {"Tuya IR",        PROTO_WIFI_TUYA},
    {"Samsung SmartThings", PROTO_WIFI_MQTT},
    {"ESP32 + IR",     PROTO_IR},
};

// Sensores de temperatura
static const BrandEntry BRANDS_TEMP[] = {
    {"ESP32 + DHT22",  PROTO_WIFI_MQTT},
    {"ESP32 + BME280", PROTO_WIFI_MQTT},
    {"ESP32 + DS18B20",PROTO_WIFI_MQTT},
    {"Sonoff TH",      PROTO_WIFI_MQTT},
    {"Aqara Temp",     PROTO_ZIGBEE},
    {"Tuya Temp",      PROTO_WIFI_TUYA},
    {"Mi Temp",        PROTO_BLE},
};

// Câmeras
static const BrandEntry BRANDS_CAMERA[] = {
    {"Intelbras VIP",  PROTO_WIFI_HTTP},
    {"Tapo C200",      PROTO_WIFI_HTTP},
    {"Wyze Cam",       PROTO_WIFI_HTTP},
    {"ESP32-CAM",      PROTO_WIFI_MQTT},
    {"Hikvision",      PROTO_WIFI_HTTP},
    {"Dahua",          PROTO_WIFI_HTTP},
};

// =====================================================
// COMANDOS POR TIPO DE DISPOSITIVO
// =====================================================

// Comandos que cada tipo aceita via MQTT
struct DeviceCommandDef {
    const char* comando;
    const char* descricao;
    bool requer_payload;   // precisa de dados extras?
};

// Lâmpada / LED Strip
static const DeviceCommandDef CMDS_LAMP[] = {
    {"ligar",        "Liga a lâmpada",          false},
    {"desligar",     "Desliga a lâmpada",        false},
    {"mudar_cor",    "Muda cor (r,g,b)",         true},
    {"ajustar_brilho","Brilho 0-100%",           true},
    {"modo",         "Modo: branco/cor/cena",    true},
    {"status",       "Retorna estado atual",     false},
};
static const uint8_t CMDS_LAMP_LEN = sizeof(CMDS_LAMP)/sizeof(CMDS_LAMP[0]);

// LED Strip (extra: efeitos)
static const DeviceCommandDef CMDS_LED_STRIP[] = {
    {"ligar",        "Liga a fita",              false},
    {"desligar",     "Desliga a fita",            false},
    {"mudar_cor",    "Cor RGB (r,g,b)",           true},
    {"efeito",       "Efeito: arco-iris/pulso/fogo", true},
    {"velocidade",   "Velocidade do efeito 0-100",true},
    {"brilho",       "Brilho 0-100%",             true},
    {"status",       "Retorna estado atual",      false},
};
static const uint8_t CMDS_LED_STRIP_LEN = sizeof(CMDS_LED_STRIP)/sizeof(CMDS_LED_STRIP[0]);

// Interruptor / Tomada
static const DeviceCommandDef CMDS_SWITCH[] = {
    {"ligar",        "Liga",                     false},
    {"desligar",     "Desliga",                  false},
    {"toggle",       "Inverte estado",            false},
    {"status",       "Estado atual",             false},
};
static const uint8_t CMDS_SWITCH_LEN = sizeof(CMDS_SWITCH)/sizeof(CMDS_SWITCH[0]);

// Ar Condicionado
static const DeviceCommandDef CMDS_AC[] = {
    {"ligar",        "Liga o AC",                false},
    {"desligar",     "Desliga o AC",             false},
    {"aumentar_temp","Aumenta temperatura 1°C",  false},
    {"diminuir_temp","Diminui temperatura 1°C",  false},
    {"set_temp",     "Define temperatura (°C)",  true},
    {"modo",         "Modo: frio/quente/auto/vent",true},
    {"status",       "Estado atual",             false},
};
static const uint8_t CMDS_AC_LEN = sizeof(CMDS_AC)/sizeof(CMDS_AC[0]);

// Ventilador
static const DeviceCommandDef CMDS_FAN[] = {
    {"ligar",              "Liga o ventilador",          false},
    {"desligar",           "Desliga o ventilador",       false},
    {"aumentar_velocidade","Aumenta velocidade",         false},
    {"diminuir_velocidade","Diminui velocidade",         false},
    {"set_velocidade",     "Velocidade 1-3",             true},
    {"oscilar",            "Liga/desliga oscilação",     true},
    {"status",             "Estado atual",              false},
};
static const uint8_t CMDS_FAN_LEN = sizeof(CMDS_FAN)/sizeof(CMDS_FAN[0]);

// TV
static const DeviceCommandDef CMDS_TV[] = {
    {"ligar",         "Liga a TV",               false},
    {"desligar",      "Desliga a TV",            false},
    {"mudar_canal",   "Muda canal (número)",     true},
    {"aumentar_volume","Aumenta volume",         false},
    {"diminuir_volume","Diminui volume",         false},
    {"mudo",          "Toggle mudo",             false},
    {"entrada",       "Muda entrada HDMI/AV",    true},
    {"status",        "Estado atual",            false},
};
static const uint8_t CMDS_TV_LEN = sizeof(CMDS_TV)/sizeof(CMDS_TV[0]);

// Sensores (só leitura)
static const DeviceCommandDef CMDS_SENSOR[] = {
    {"consultar",     "Leitura atual",           false},
    {"historico",     "Últimas N leituras",      true},
    {"calibrar",      "Calibração do sensor",    true},
    {"intervalo",     "Intervalo de publicação", true},
};
static const uint8_t CMDS_SENSOR_LEN = sizeof(CMDS_SENSOR)/sizeof(CMDS_SENSOR[0]);

// Sensor de fumaça / gás (+ teste)
static const DeviceCommandDef CMDS_SENSOR_ALARM[] = {
    {"consultar",     "Estado atual",            false},
    {"testar",        "Dispara teste de alarme", false},
    {"silenciar",     "Silencia alarme",         false},
    {"historico",     "Histórico de eventos",    true},
};
static const uint8_t CMDS_SENSOR_ALARM_LEN = sizeof(CMDS_SENSOR_ALARM)/sizeof(CMDS_SENSOR_ALARM[0]);

// Câmera IP
static const DeviceCommandDef CMDS_CAMERA[] = {
    {"ligar",         "Liga stream",             false},
    {"desligar",      "Desliga stream",          false},
    {"capturar",      "Captura imagem",          false},
    {"girar",         "Movimenta PTZ",           true},
    {"gravar",        "Inicia/para gravação",    true},
    {"status",        "Estado atual",            false},
};
static const uint8_t CMDS_CAMERA_LEN = sizeof(CMDS_CAMERA)/sizeof(CMDS_CAMERA[0]);

// Alarme
static const DeviceCommandDef CMDS_ALARM[] = {
    {"armar",         "Arma o alarme",           false},
    {"desarmar",      "Desarma o alarme",        false},
    {"disparar",      "Dispara manualmente",     false},
    {"silenciar",     "Silencia sirene",         false},
    {"status",        "Estado atual",            false},
};
static const uint8_t CMDS_ALARM_LEN = sizeof(CMDS_ALARM)/sizeof(CMDS_ALARM[0]);

// Fechadura
static const DeviceCommandDef CMDS_LOCK[] = {
    {"trancar",       "Tranca a fechadura",      false},
    {"destrancar",    "Destranca a fechadura",   false},
    {"status",        "Estado (trancado/aberto)",false},
    {"historico",     "Histórico de acessos",    true},
};
static const uint8_t CMDS_LOCK_LEN = sizeof(CMDS_LOCK)/sizeof(CMDS_LOCK[0]);

// =====================================================
// FORMATO JSON PUBLICADO POR CADA TIPO
// =====================================================
// Estes são os campos que cada dispositivo PUBLICA
// no tópico  <topic_base>/devices/<device_id>/data

// Sensor de temperatura:
// { "device_id":"...", "tipo":"temp_sensor",
//   "temp_c": 24.5, "timestamp":"..." }

// Sensor de umidade:
// { "device_id":"...", "tipo":"humidity_sensor",
//   "umidade": 65.2, "timestamp":"..." }

// Sensor de fumaça / gás:
// { "device_id":"...", "tipo":"smoke_sensor",
//   "detectado": false, "valor_raw": 120, "timestamp":"..." }

// Sensor de movimento:
// { "device_id":"...", "tipo":"motion_sensor",
//   "movimento": true, "timestamp":"..." }

// Sensor de porta:
// { "device_id":"...", "tipo":"door_sensor",
//   "aberto": false, "timestamp":"..." }

// Lâmpada / Switch / Tomada:
// { "device_id":"...", "tipo":"lamp",
//   "ligado": true, "brilho": 80, "cor":"#FFFFFF", "timestamp":"..." }

// Câmera:
// { "device_id":"...", "tipo":"camera",
//   "stream_url":"rtsp://...", "gravando": false, "timestamp":"..." }

// =====================================================
// ESTRUTURA DE CACHE DE DISPOSITIVOS
// (equivalente ao cache Bluetooth do celular)
// =====================================================

#define MAX_CACHED_DEVICES 32
#define DEVICE_CACHE_NS    "dev-cache"

struct CachedDevice {
    char     device_id[24];    // ID único (ex: "lamp_sala_01")
    char     nome[40];         // Nome amigável (ex: "Lâmpada Sala")
    char     mac[18];          // MAC WiFi ou BLE
    char     ip[16];           // IP na rede (WiFi)
    char     marca[28];        // ex: "Sonoff", "Tuya", "ESP32"
    char     modelo[28];       // ex: "Mini R2", "Basic", "Custom"
    char     firmware[16];     // versão do firmware
    char     room[24];         // Cômodo (ex: "Sala", "Quarto 1")
    DeviceType  tipo;          // enum DeviceType
    DeviceProtocol protocolo;  // enum DeviceProtocol
    uint8_t  rssi_ultimo;      // último RSSI visto
    uint32_t ultimo_visto;     // timestamp Unix
    uint32_t primeiro_visto;   // timestamp Unix (quando foi descoberto)
    uint32_t total_msgs;       // total de mensagens recebidas
    bool     online;           // está online agora?
    bool     favoritado;       // usuário marcou como favorito
};

static CachedDevice deviceCache[MAX_CACHED_DEVICES];
static uint8_t deviceCacheCount = 0;
static bool deviceCacheCarregado = false;

// =====================================================
// FUNÇÕES DO CACHE DE DISPOSITIVOS
// =====================================================

// Salva um dispositivo no cache (NVS)
inline void saveDeviceToCache(const CachedDevice& dev) {
    Preferences p;
    String ns = String(DEVICE_CACHE_NS);
    p.begin(ns.c_str(), false);

    // Chave única por device_id (max 15 chars no NVS)
    String key = String(dev.device_id).substring(0, 14);

    // Serializa como JSON compacto para economizar NVS
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"n\":\"%s\",\"m\":\"%s\",\"ip\":\"%s\","
        "\"mk\":\"%s\",\"md\":\"%s\",\"rm\":\"%s\","
        "\"t\":%d,\"p\":%d,\"fv\":%lu,\"tm\":%lu}",
        dev.nome, dev.mac, dev.ip,
        dev.marca, dev.modelo, dev.room,
        (int)dev.tipo, (int)dev.protocolo,
        (unsigned long)dev.primeiro_visto,
        (unsigned long)dev.total_msgs
    );
    p.putString(key.c_str(), buf);
    p.end();
}

// Carrega todos os dispositivos do NVS para RAM
inline void loadDeviceCache() {
    if (deviceCacheCarregado) return;
    deviceCacheCount = 0;

    Preferences p;
    p.begin(DEVICE_CACHE_NS, true);
    // NVS não tem iteração fácil — carregamos via índice salvo
    uint8_t count = p.getUChar("_count", 0);

    for (uint8_t i = 0; i < count && i < MAX_CACHED_DEVICES; i++) {
        char idKey[16];
        snprintf(idKey, sizeof(idKey), "_id%d", i);
        String devId = p.getString(idKey, "");
        if (devId.isEmpty()) continue;

        String key = devId.substring(0, 14);
        String json = p.getString(key.c_str(), "");
        if (json.isEmpty()) continue;

        CachedDevice& dev = deviceCache[deviceCacheCount];
        strlcpy(dev.device_id, devId.c_str(), sizeof(dev.device_id));
        dev.online = false;
        dev.favoritado = false;
        dev.rssi_ultimo = 0;
        dev.ultimo_visto = 0;
        // Parsing básico dos campos principais
        // (parsing completo via ArduinoJson se necessário)
        deviceCacheCount++;
    }
    p.end();
    deviceCacheCarregado = true;
    Serial.printf("[CACHE] %d dispositivos carregados do NVS\n", deviceCacheCount);
}

// Busca dispositivo no cache por device_id
inline CachedDevice* findDevice(const char* deviceId) {
    for (uint8_t i = 0; i < deviceCacheCount; i++) {
        if (strcmp(deviceCache[i].device_id, deviceId) == 0)
            return &deviceCache[i];
    }
    return nullptr;
}

// Busca dispositivo no cache por MAC
inline CachedDevice* findDeviceByMac(const char* mac) {
    for (uint8_t i = 0; i < deviceCacheCount; i++) {
        if (strcasecmp(deviceCache[i].mac, mac) == 0)
            return &deviceCache[i];
    }
    return nullptr;
}

// Registra ou atualiza dispositivo no cache
// (igual o celular que guarda nome + info quando vê um BT novo)
inline CachedDevice* registerDevice(
    const char* deviceId,
    const char* nome,
    const char* mac,
    const char* ip,
    const char* marca,
    const char* modelo,
    const char* room,
    DeviceType tipo,
    DeviceProtocol protocolo,
    uint32_t now,
    int8_t rssi = 0)
{
    // Tenta encontrar existente
    CachedDevice* existing = findDevice(deviceId);

    if (existing) {
        // Atualiza campos dinâmicos
        strlcpy(existing->ip,          ip,    sizeof(existing->ip));
        existing->online        = true;
        existing->ultimo_visto  = now;
        existing->rssi_ultimo   = (uint8_t)(rssi + 128);
        existing->total_msgs++;
        if (nome && nome[0]) strlcpy(existing->nome, nome, sizeof(existing->nome));
        saveDeviceToCache(*existing);
        return existing;
    }

    // Novo dispositivo — adiciona ao cache
    if (deviceCacheCount >= MAX_CACHED_DEVICES) {
        Serial.println("[CACHE] ⚠️  Cache cheio, descartando dispositivo mais antigo");
        // Remove o mais antigo (índice 0, shift array)
        memmove(&deviceCache[0], &deviceCache[1],
                sizeof(CachedDevice) * (MAX_CACHED_DEVICES - 1));
        deviceCacheCount = MAX_CACHED_DEVICES - 1;
    }

    CachedDevice& dev = deviceCache[deviceCacheCount];
    memset(&dev, 0, sizeof(CachedDevice));

    strlcpy(dev.device_id,    deviceId, sizeof(dev.device_id));
    strlcpy(dev.nome,         nome,     sizeof(dev.nome));
    strlcpy(dev.mac,          mac,      sizeof(dev.mac));
    strlcpy(dev.ip,           ip,       sizeof(dev.ip));
    strlcpy(dev.marca,        marca,    sizeof(dev.marca));
    strlcpy(dev.modelo,       modelo,   sizeof(dev.modelo));
    strlcpy(dev.room,         room,     sizeof(dev.room));
    dev.tipo           = tipo;
    dev.protocolo      = protocolo;
    dev.online         = true;
    dev.favoritado     = false;
    dev.primeiro_visto = now;
    dev.ultimo_visto   = now;
    dev.total_msgs     = 1;
    dev.rssi_ultimo    = (uint8_t)(rssi + 128);

    deviceCacheCount++;

    saveDeviceToCache(dev);

    Serial.printf("[CACHE] ✅ Novo dispositivo: %s (%s) tipo=%d\n",
                  dev.nome, dev.device_id, (int)dev.tipo);

    return &deviceCache[deviceCacheCount - 1];
}

// Marca dispositivo como offline
inline void setDeviceOffline(const char* deviceId) {
    CachedDevice* dev = findDevice(deviceId);
    if (dev) { dev->online = false; saveDeviceToCache(*dev); }
}

// Retorna nome do tipo como string
inline const char* deviceTypeName(DeviceType t) {
    switch (t) {
        case DEV_LAMP:            return "Lâmpada Inteligente";
        case DEV_LED_STRIP:       return "Fita de LED";
        case DEV_SWITCH:          return "Interruptor Inteligente";
        case DEV_OUTLET:          return "Tomada Inteligente";
        case DEV_AC:              return "Ar Condicionado";
        case DEV_FAN:             return "Ventilador";
        case DEV_TV:              return "Televisão";
        case DEV_TEMP_SENSOR:     return "Sensor de Temperatura";
        case DEV_HUMIDITY_SENSOR: return "Sensor de Umidade";
        case DEV_SMOKE_SENSOR:    return "Sensor de Fumaça";
        case DEV_GAS_SENSOR:      return "Sensor de Gás";
        case DEV_MOTION_SENSOR:   return "Sensor de Movimento";
        case DEV_DOOR_SENSOR:     return "Sensor de Porta";
        case DEV_CAMERA:          return "Câmera IP";
        case DEV_ALARM:           return "Alarme";
        case DEV_LOCK:            return "Fechadura Inteligente";
        case DEV_GATEWAY:         return "Gateway IoT";
        default:                  return "Dispositivo Desconhecido";
    }
}

// Retorna nome do protocolo como string
inline const char* protocolName(DeviceProtocol p) {
    switch (p) {
        case PROTO_WIFI_MQTT: return "WiFi/MQTT";
        case PROTO_WIFI_TUYA: return "WiFi/Tuya";
        case PROTO_WIFI_HTTP: return "WiFi/HTTP";
        case PROTO_BLE:       return "BLE";
        case PROTO_ZIGBEE:    return "Zigbee";
        case PROTO_ZWAVE:     return "Z-Wave";
        case PROTO_IR:        return "IR";
        case PROTO_MATTER:    return "Matter";
        default:              return "Desconhecido";
    }
}

// =====================================================
// TÓPICOS MQTT POR DISPOSITIVO
// ─────────────────────────────────────────────────
// Estrutura:
//   <topic_base>/devices/<device_id>/data     ← dispositivo publica dados
//   <topic_base>/devices/<device_id>/cmd      ← gateway envia comandos
//   <topic_base>/devices/<device_id>/status   ← online/offline/info
//   <topic_base>/devices/<device_id>/response ← resposta a comandos
//   <topic_base>/devices/announce             ← dispositivo anuncia presença
// =====================================================

inline String topicDeviceData(const String& base, const char* deviceId) {
    return base + "/devices/" + String(deviceId) + "/data";
}
inline String topicDeviceCmd(const String& base, const char* deviceId) {
    return base + "/devices/" + String(deviceId) + "/cmd";
}
inline String topicDeviceStatus(const String& base, const char* deviceId) {
    return base + "/devices/" + String(deviceId) + "/status";
}
inline String topicDeviceResponse(const String& base, const char* deviceId) {
    return base + "/devices/" + String(deviceId) + "/response";
}
inline String topicDeviceAnnounce(const String& base) {
    return base + "/devices/announce";
}
// Wildcard para subscrever todos os dispositivos de uma vez
inline String topicAllDevices(const String& base) {
    return base + "/devices/+/data";
}

// =====================================================
// PARSER DE ANNOUNCE
// Quando um dispositivo entra na rede, ele publica em
// <topic_base>/devices/announce com seus dados.
// O gateway processa e registra no cache.
//
// Formato esperado do announce:
// {
//   "device_id": "lamp_sala_01",
//   "nome":      "Lâmpada Sala",
//   "mac":       "AA:BB:CC:DD:EE:FF",
//   "ip":        "192.168.1.100",
//   "marca":     "Sonoff",
//   "modelo":    "B02-F-A60",
//   "firmware":  "1.4.0",
//   "room":      "Sala",
//   "tipo":      1,
//   "protocolo": 1
// }
// =====================================================

inline CachedDevice* processAnnounce(const String& json, uint32_t now) {
    // Parsing básico sem ArduinoJson para economizar stack
    auto extract = [&](const char* key) -> String {
        String search = String("\"") + key + "\":\"";
        int idx = json.indexOf(search);
        if (idx < 0) {
            // Tenta sem aspas (número)
            search = String("\"") + key + "\":";
            idx = json.indexOf(search);
            if (idx < 0) return "";
            idx += search.length();
            int end = json.indexOf(",", idx);
            if (end < 0) end = json.indexOf("}", idx);
            return json.substring(idx, end);
        }
        idx += search.length();
        int end = json.indexOf("\"", idx);
        return json.substring(idx, end);
    };

    String deviceId = extract("device_id");
    String nome     = extract("nome");
    String mac      = extract("mac");
    String ip       = extract("ip");
    String marca    = extract("marca");
    String modelo   = extract("modelo");
    String room     = extract("room");
    int    tipo     = extract("tipo").toInt();
    int    proto    = extract("protocolo").toInt();

    if (deviceId.isEmpty()) {
        Serial.println("[CACHE] ⚠️  Announce sem device_id, ignorado");
        return nullptr;
    }

    return registerDevice(
        deviceId.c_str(), nome.c_str(), mac.c_str(), ip.c_str(),
        marca.c_str(), modelo.c_str(), room.c_str(),
        (DeviceType)tipo, (DeviceProtocol)proto, now
    );
}

// =====================================================
// SERIALIZAÇÃO DO CACHE PARA MQTT
// Publica lista completa de dispositivos conhecidos
// =====================================================

// Retorna JSON de um dispositivo para publicar via MQTT
inline String deviceToJson(const CachedDevice& dev) {
    char buf[384];
    snprintf(buf, sizeof(buf),
        "{\"device_id\":\"%s\",\"nome\":\"%s\",\"mac\":\"%s\","
        "\"ip\":\"%s\",\"marca\":\"%s\",\"modelo\":\"%s\","
        "\"room\":\"%s\",\"tipo\":%d,\"tipo_nome\":\"%s\","
        "\"protocolo\":%d,\"protocolo_nome\":\"%s\","
        "\"online\":%s,\"favoritado\":%s,"
        "\"ultimo_visto\":%lu,\"total_msgs\":%lu}",
        dev.device_id, dev.nome, dev.mac,
        dev.ip, dev.marca, dev.modelo,
        dev.room, (int)dev.tipo, deviceTypeName(dev.tipo),
        (int)dev.protocolo, protocolName(dev.protocolo),
        dev.online ? "true" : "false",
        dev.favoritado ? "true" : "false",
        (unsigned long)dev.ultimo_visto,
        (unsigned long)dev.total_msgs
    );
    return String(buf);
}

// =====================================================
// INFERÊNCIA DE TIPO POR OUI/SSID/NOME
// Liga o classificador WiFi/BLE com o sistema de cache
// =====================================================

inline DeviceType inferDeviceType(const char* label) {
    String l = String(label);
    l.toLowerCase();

    if (l.indexOf("lâmpada")   >= 0 || l.indexOf("lamp")    >= 0 ||
        l.indexOf("bulb")      >= 0 || l.indexOf("hue")     >= 0 ||
        l.indexOf("wiz")       >= 0) return DEV_LAMP;
    if (l.indexOf("fita")      >= 0 || l.indexOf("led strip")>= 0 ||
        l.indexOf("wled")      >= 0 || l.indexOf("govee")   >= 0) return DEV_LED_STRIP;
    if (l.indexOf("interruptor")>=0 || l.indexOf("switch")  >= 0 ||
        l.indexOf("sonoff")    >= 0 || l.indexOf("shelly")  >= 0) return DEV_SWITCH;
    if (l.indexOf("tomada")    >= 0 || l.indexOf("plug")    >= 0 ||
        l.indexOf("outlet")    >= 0) return DEV_OUTLET;
    if (l.indexOf("ar condic") >= 0 || l.indexOf("ac")      >= 0 ||
        l.indexOf("aircon")    >= 0) return DEV_AC;
    if (l.indexOf("ventilador")>= 0 || l.indexOf("fan")     >= 0) return DEV_FAN;
    if (l.indexOf("televisão") >= 0 || l.indexOf("tv")      >= 0 ||
        l.indexOf("smart tv")  >= 0) return DEV_TV;
    if (l.indexOf("temperatura")>=0 || l.indexOf("temp")    >= 0 ||
        l.indexOf("termômetro")>= 0) return DEV_TEMP_SENSOR;
    if (l.indexOf("umidade")   >= 0 || l.indexOf("humidity")>= 0) return DEV_HUMIDITY_SENSOR;
    if (l.indexOf("fumaça")    >= 0 || l.indexOf("smoke")   >= 0) return DEV_SMOKE_SENSOR;
    if (l.indexOf("gás")       >= 0 || l.indexOf("gas")     >= 0) return DEV_GAS_SENSOR;
    if (l.indexOf("movimento") >= 0 || l.indexOf("motion")  >= 0 ||
        l.indexOf("pir")       >= 0) return DEV_MOTION_SENSOR;
    if (l.indexOf("porta")     >= 0 || l.indexOf("door")    >= 0 ||
        l.indexOf("janela")    >= 0) return DEV_DOOR_SENSOR;
    if (l.indexOf("câmera")    >= 0 || l.indexOf("camera")  >= 0 ||
        l.indexOf("cam")       >= 0) return DEV_CAMERA;
    if (l.indexOf("alarme")    >= 0 || l.indexOf("alarm")   >= 0 ||
        l.indexOf("sirene")    >= 0) return DEV_ALARM;
    if (l.indexOf("fechadura") >= 0 || l.indexOf("lock")    >= 0) return DEV_LOCK;

    return DEV_UNKNOWN;
}
