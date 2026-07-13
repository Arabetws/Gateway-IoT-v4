// =====================================================
// device_classifier.h
// Classificador de dispositivos WiFi e BLE
// Compatível com: IoT Platform ESP32-S3 Gateway v3.0
// Depende de: table.h (OUIEntry, lookupOUI,
//             BLEServiceEntry, lookupBLEServiceUUID)
// =====================================================

#pragma once
#include <Arduino.h>
// NÃO inclui table.h aqui — já incluído pelo main.cpp antes deste header

// =====================================================
// ESTRUTURA DE RETORNO
// =====================================================

struct DeviceProfile {
    char    vendor[28];     // fabricante (do OUI ou heurística)
    char    label[48];      // categoria/tipo legível
    char    protocol[24];   // protocolo detectado (WiFi, BLE, Zigbee, etc.)
    uint8_t confidence;     // 0–100
    bool    is_mobile;      // celular/tablet?
    bool    is_iot;         // dispositivo IoT/smart home?
    bool    is_sensor;      // é um sensor? (leitura de dados)
    bool    is_actuator;    // é um atuador? (executa ações)
};

// =====================================================
// HELPERS INTERNOS — detecção por SSID
// =====================================================

static void _ssidClassify(const char* ssid,
                           char* label, bool* isMobile,
                           bool* isIot, uint8_t* conf)
{
    String s = String(ssid);
    s.toLowerCase();

    // Hotspots móveis
    if (s.indexOf("iphone")    >= 0) { strlcpy(label,"iPhone Hotspot",      48); *isMobile=true;  *isIot=false; *conf=92; return; }
    if (s.indexOf("ipad")      >= 0) { strlcpy(label,"iPad Hotspot",        48); *isMobile=true;  *isIot=false; *conf=90; return; }
    if (s.indexOf("galaxy")    >= 0) { strlcpy(label,"Samsung Galaxy",      48); *isMobile=true;  *isIot=false; *conf=90; return; }
    if (s.indexOf("android")   >= 0) { strlcpy(label,"Smartphone Android",  48); *isMobile=true;  *isIot=false; *conf=85; return; }
    if (s.indexOf("xiaomi")    >= 0) { strlcpy(label,"Xiaomi Hotspot",      48); *isMobile=true;  *isIot=false; *conf=88; return; }
    if (s.indexOf("redmi")     >= 0) { strlcpy(label,"Redmi Hotspot",       48); *isMobile=true;  *isIot=false; *conf=88; return; }
    if (s.indexOf("motorola")  >= 0) { strlcpy(label,"Motorola Hotspot",    48); *isMobile=true;  *isIot=false; *conf=88; return; }
    if (s.indexOf("hotspot")   >= 0) { strlcpy(label,"Hotspot Móvel",       48); *isMobile=true;  *isIot=false; *conf=80; return; }

    // IoT / Smart Home por SSID
    if (s.indexOf("sonoff")    >= 0) { strlcpy(label,"Sonoff IoT",          48); *isMobile=false; *isIot=true;  *conf=92; return; }
    if (s.indexOf("shelly")    >= 0) { strlcpy(label,"Shelly IoT",          48); *isMobile=false; *isIot=true;  *conf=92; return; }
    if (s.indexOf("tasmota")   >= 0) { strlcpy(label,"Tasmota Device",      48); *isMobile=false; *isIot=true;  *conf=93; return; }
    if (s.indexOf("tuya")      >= 0) { strlcpy(label,"Tuya Smart Device",   48); *isMobile=false; *isIot=true;  *conf=90; return; }
    if (s.indexOf("ewelink")   >= 0) { strlcpy(label,"eWeLink Device",      48); *isMobile=false; *isIot=true;  *conf=90; return; }
    if (s.indexOf("esp_")      >= 0 ||
        s.indexOf("esp32")     >= 0 ||
        s.indexOf("esp8266")   >= 0) { strlcpy(label,"Dispositivo ESP",     48); *isMobile=false; *isIot=true;  *conf=88; return; }
    if (s.indexOf("wled")      >= 0) { strlcpy(label,"WLED LED Strip",      48); *isMobile=false; *isIot=true;  *conf=93; return; }
    if (s.indexOf("esphome")   >= 0) { strlcpy(label,"ESPHome Device",      48); *isMobile=false; *isIot=true;  *conf=93; return; }

    // Câmeras
    if (s.indexOf("hikcam")    >= 0 ||
        s.indexOf("hikvision") >= 0) { strlcpy(label,"Câmera Hikvision",    48); *isMobile=false; *isIot=true;  *conf=92; return; }
    if (s.indexOf("dahua")     >= 0) { strlcpy(label,"Câmera Dahua",        48); *isMobile=false; *isIot=true;  *conf=92; return; }
    if (s.indexOf("ipcam")     >= 0 ||
        s.indexOf("cam_")      >= 0 ||
        s.indexOf("camera")    >= 0) { strlcpy(label,"Câmera IP",           48); *isMobile=false; *isIot=true;  *conf=78; return; }

    // Roteadores / ISP
    if (s.indexOf("tp-link")   >= 0 ||
        s.indexOf("tplink")    >= 0) { strlcpy(label,"Roteador TP-Link",    48); *isMobile=false; *isIot=false; *conf=90; return; }
    if (s.indexOf("intelbras") >= 0) { strlcpy(label,"Roteador Intelbras",  48); *isMobile=false; *isIot=false; *conf=90; return; }
    if (s.indexOf("d-link")    >= 0 ||
        s.indexOf("dlink")     >= 0) { strlcpy(label,"Roteador D-Link",     48); *isMobile=false; *isIot=false; *conf=90; return; }
    if (s.indexOf("gpon")      >= 0 ||
        s.indexOf("claro")     >= 0 ||
        s.indexOf("vivo fiber")>= 0 ||
        s.indexOf("tim_")      >= 0) { strlcpy(label,"Modem ISP",           48); *isMobile=false; *isIot=false; *conf=80; return; }

    // Impressoras
    if (s.indexOf("hp-print")  >= 0 ||
        s.indexOf("direct")    >= 0) { strlcpy(label,"Impressora",          48); *isMobile=false; *isIot=false; *conf=82; return; }

    // Sem padrão reconhecido
    strlcpy(label, "Rede WiFi", 48);
    *isMobile = false; *isIot = false; *conf = 15;
}

// =====================================================
// HELPERS INTERNOS — flags IoT/mobile pelo tipo OUI
// =====================================================

static void _ouiFlags(const char* ouiTipo,
                      bool* isMobile, bool* isIot)
{
    String t = String(ouiTipo);
    t.toLowerCase();

    *isIot    = (t.indexOf("inteligente") >= 0 ||
                 t.indexOf("iot")         >= 0 ||
                 t.indexOf("câmera")      >= 0 ||
                 t.indexOf("sensor")      >= 0 ||
                 t.indexOf("lâmpada")     >= 0 ||
                 t.indexOf("tomada")      >= 0 ||
                 t.indexOf("robô")        >= 0 ||
                 t.indexOf("zigbee")      >= 0 ||
                 t.indexOf("esp")         >= 0 ||
                 t.indexOf("hub")         >= 0 ||
                 t.indexOf("nest")        >= 0 ||
                 t.indexOf("hue")         >= 0 ||
                 t.indexOf("wemo")        >= 0 ||
                 t.indexOf("echo")        >= 0 ||
                 t.indexOf("firetv")      >= 0 ||
                 t.indexOf("chromecast")  >= 0 ||
                 t.indexOf("beacon")      >= 0);

    *isMobile = (t.indexOf("iphone")      >= 0 ||
                 t.indexOf("homepod")     >= 0 ||
                 t.indexOf("mac")         >= 0 ||
                 t.indexOf("smartphone")  >= 0 ||
                 t.indexOf("smart tv")    >= 0 ||
                 t.indexOf("thinq")       >= 0 ||
                 t.indexOf("xbox")        >= 0 ||
                 t.indexOf("surface")     >= 0);
}

// =====================================================
// HELPERS INTERNOS — sensor/atuador pelo label
// =====================================================

static void _detectSensorActuator(const char* label,
                                   bool* isSensor,
                                   bool* isActuator)
{
    String l = String(label);
    l.toLowerCase();

    *isSensor   = (l.indexOf("sensor")      >= 0 ||
                   l.indexOf("câmera")      >= 0 ||
                   l.indexOf("camera")      >= 0 ||
                   l.indexOf("monitor")     >= 0 ||
                   l.indexOf("detector")    >= 0 ||
                   l.indexOf("termostato")  >= 0 ||
                   l.indexOf("estação")     >= 0 ||
                   l.indexOf("pressão")     >= 0 ||
                   l.indexOf("oxímetro")    >= 0 ||
                   l.indexOf("balança")     >= 0 ||
                   l.indexOf("fitbit")      >= 0 ||
                   l.indexOf("mi band")     >= 0 ||
                   l.indexOf("pulseira")    >= 0 ||
                   l.indexOf("cardíaco")    >= 0 ||
                   l.indexOf("saúde")       >= 0 ||
                   l.indexOf("mi watch")    >= 0 ||
                   l.indexOf("smartwatch")  >= 0 ||
                   l.indexOf("garmin")      >= 0 ||
                   l.indexOf("beacon")      >= 0);

    *isActuator = (l.indexOf("lâmpada")     >= 0 ||
                   l.indexOf("lamp")        >= 0 ||
                   l.indexOf("light")       >= 0 ||
                   l.indexOf("bulb")        >= 0 ||
                   l.indexOf("tomada")      >= 0 ||
                   l.indexOf("plug")        >= 0 ||
                   l.indexOf("switch")      >= 0 ||
                   l.indexOf("relé")        >= 0 ||
                   l.indexOf("fechadura")   >= 0 ||
                   l.indexOf("lock")        >= 0 ||
                   l.indexOf("motor")       >= 0 ||
                   l.indexOf("válvula")     >= 0 ||
                   l.indexOf("valve")       >= 0 ||
                   l.indexOf("aspirador")   >= 0 ||
                   l.indexOf("robô")        >= 0 ||
                   l.indexOf("controle")    >= 0 ||
                   l.indexOf("remote")      >= 0 ||
                   l.indexOf("wled")        >= 0 ||
                   l.indexOf("led strip")   >= 0 ||
                   l.indexOf("sonoff")      >= 0 ||
                   l.indexOf("shelly")      >= 0);
}

// =====================================================
// HELPERS INTERNOS — protocolo WiFi pelo label/vendor
// =====================================================

static void _detectProtocolWiFi(const char* label,
                                  const char* vendor,
                                  bool isIot,
                                  char* protocol,
                                  size_t protLen)
{
    String l = String(label);
    String v = String(vendor);
    l.toLowerCase();
    v.toLowerCase();

    if (l.indexOf("zigbee")     >= 0 ||
        v.indexOf("aqara")      >= 0 ||
        v.indexOf("ikea")       >= 0) { strlcpy(protocol, "Zigbee",      protLen); return; }
    if (l.indexOf("tasmota")    >= 0 ||
        l.indexOf("esphome")    >= 0 ||
        l.indexOf("esp")        >= 0) { strlcpy(protocol, "WiFi/MQTT",   protLen); return; }
    if (l.indexOf("tuya")       >= 0 ||
        v.indexOf("tuya")       >= 0) { strlcpy(protocol, "WiFi/Tuya",   protLen); return; }
    if (l.indexOf("matter")     >= 0) { strlcpy(protocol, "Matter",      protLen); return; }
    if (l.indexOf("homekit")    >= 0) { strlcpy(protocol, "HomeKit",     protLen); return; }
    if (l.indexOf("chromecast") >= 0 ||
        v.indexOf("google")     >= 0) { strlcpy(protocol, "Cast/mDNS",   protLen); return; }
    if (l.indexOf("echo")       >= 0 ||
        v.indexOf("amazon")     >= 0) { strlcpy(protocol, "WiFi/Alexa",  protLen); return; }
    if (l.indexOf("câmera")     >= 0 ||
        l.indexOf("camera")     >= 0) { strlcpy(protocol, "WiFi/RTSP",   protLen); return; }
    if (isIot)                        { strlcpy(protocol, "WiFi/MQTT",   protLen); return; }
    strlcpy(protocol, "WiFi", protLen);
}

// =====================================================
// HELPERS INTERNOS — protocolo BLE pelo label/UUID
// =====================================================

static void _detectProtocolBLE(const char* label,
                                 const char* uuids,
                                 bool isIot,
                                 char* protocol,
                                 size_t protLen)
{
    String l = String(label);
    String u = String(uuids ? uuids : "");
    l.toLowerCase();
    u.toUpperCase();

    if (u.indexOf("FFF0")       >= 0 ||
        u.indexOf("FFF1")       >= 0) { strlcpy(protocol, "BLE/Tuya",     protLen); return; }
    if (u.indexOf("FE95")       >= 0 ||
        u.indexOf("FE96")       >= 0) { strlcpy(protocol, "BLE/Xiaomi",   protLen); return; }
    if (u.indexOf("FEA0")       >= 0 ||
        u.indexOf("FE2C")       >= 0) { strlcpy(protocol, "BLE/FastPair", protLen); return; }
    if (u.indexOf("FEAA")       >= 0) { strlcpy(protocol, "Eddystone",    protLen); return; }
    if (u.indexOf("FEB3")       >= 0) { strlcpy(protocol, "iBeacon",      protLen); return; }
    if (u.indexOf("FDCD")       >= 0) { strlcpy(protocol, "BLE/IKEA",     protLen); return; }
    if (u.indexOf("FE59")       >= 0) { strlcpy(protocol, "BLE/NordicDFU",protLen); return; }
    if (u.indexOf("180D")       >= 0 ||
        u.indexOf("181A")       >= 0 ||
        u.indexOf("181C")       >= 0 ||
        u.indexOf("1810")       >= 0) { strlcpy(protocol, "BLE/GATT",     protLen); return; }
    if (u.indexOf("1812")       >= 0) { strlcpy(protocol, "BLE/HID",      protLen); return; }
    if (l.indexOf("beacon")     >= 0) { strlcpy(protocol, "BLE/Beacon",   protLen); return; }
    if (isIot)                        { strlcpy(protocol, "BLE/IoT",      protLen); return; }
    strlcpy(protocol, "BLE", protLen);
}

// =====================================================
// HELPERS INTERNOS — detecção BLE por nome
// =====================================================

static void _bleNameClassify(const char* nome,
                              char* label, bool* isMobile,
                              bool* isIot, uint8_t* conf)
{
    String s = String(nome);
    s.toLowerCase();

    if (s.indexOf("iphone")     >= 0) { strlcpy(label,"iPhone",              48); *isMobile=true;  *isIot=false; *conf=92; return; }
    if (s.indexOf("ipad")       >= 0) { strlcpy(label,"iPad",                48); *isMobile=true;  *isIot=false; *conf=92; return; }
    if (s.indexOf("airpods")    >= 0) { strlcpy(label,"AirPods",             48); *isMobile=false; *isIot=false; *conf=95; return; }
    if (s.indexOf("galaxy")     >= 0) { strlcpy(label,"Samsung Galaxy",      48); *isMobile=true;  *isIot=false; *conf=90; return; }
    if (s.indexOf("xiaomi")     >= 0 ||
        s.indexOf("redmi")      >= 0) { strlcpy(label,"Xiaomi",              48); *isMobile=true;  *isIot=false; *conf=90; return; }
    if (s.indexOf("mi band")    >= 0 ||
        s.indexOf("miband")     >= 0) { strlcpy(label,"Mi Band",             48); *isMobile=false; *isIot=true;  *conf=95; return; }
    if (s.indexOf("mi watch")   >= 0) { strlcpy(label,"Mi Watch",            48); *isMobile=false; *isIot=true;  *conf=95; return; }
    if (s.indexOf("fitbit")     >= 0) { strlcpy(label,"Fitbit",              48); *isMobile=false; *isIot=true;  *conf=95; return; }
    if (s.indexOf("garmin")     >= 0) { strlcpy(label,"Garmin",              48); *isMobile=false; *isIot=true;  *conf=95; return; }
    if (s.indexOf("apple watch")>= 0) { strlcpy(label,"Apple Watch",         48); *isMobile=false; *isIot=false; *conf=95; return; }
    if (s.indexOf("watch")      >= 0) { strlcpy(label,"Smartwatch",          48); *isMobile=false; *isIot=true;  *conf=72; return; }
    if (s.indexOf("band")       >= 0) { strlcpy(label,"Pulseira Fitness",    48); *isMobile=false; *isIot=true;  *conf=70; return; }
    if (s.indexOf("buds")       >= 0 ||
        s.indexOf("earphone")   >= 0 ||
        s.indexOf("headphone")  >= 0 ||
        s.indexOf("fone")       >= 0) { strlcpy(label,"Fone Bluetooth",      48); *isMobile=false; *isIot=false; *conf=82; return; }
    if (s.indexOf("jbl")        >= 0 ||
        s.indexOf("speaker")    >= 0 ||
        s.indexOf("caixa")      >= 0) { strlcpy(label,"Caixa de Som BT",     48); *isMobile=false; *isIot=false; *conf=85; return; }
    if (s.indexOf("keyboard")   >= 0 ||
        s.indexOf("teclado")    >= 0) { strlcpy(label,"Teclado Bluetooth",   48); *isMobile=false; *isIot=false; *conf=88; return; }
    if (s.indexOf("mouse")      >= 0) { strlcpy(label,"Mouse Bluetooth",     48); *isMobile=false; *isIot=false; *conf=88; return; }
    if (s.indexOf("chromecast") >= 0 ||
        s.indexOf("firetv")     >= 0 ||
        s.indexOf("android tv") >= 0) { strlcpy(label,"Smart TV / Stick",    48); *isMobile=false; *isIot=false; *conf=85; return; }
    if (s.indexOf("beacon")     >= 0 ||
        s.indexOf("eddystone")  >= 0 ||
        s.indexOf("ibeacon")    >= 0) { strlcpy(label,"Beacon BLE",          48); *isMobile=false; *isIot=true;  *conf=90; return; }
    if (s.indexOf("scale")      >= 0 ||
        s.indexOf("balan")      >= 0) { strlcpy(label,"Balança Smart",       48); *isMobile=false; *isIot=true;  *conf=85; return; }
    if (s.indexOf("bulb")       >= 0 ||
        s.indexOf("lamp")       >= 0 ||
        s.indexOf("light")      >= 0) { strlcpy(label,"Lâmpada Smart",       48); *isMobile=false; *isIot=true;  *conf=82; return; }
    if (s.indexOf("lock")       >= 0) { strlcpy(label,"Fechadura Smart",     48); *isMobile=false; *isIot=true;  *conf=82; return; }
    if (s.indexOf("sensor")     >= 0) { strlcpy(label,"Sensor BLE",          48); *isMobile=false; *isIot=true;  *conf=78; return; }
    if (s.indexOf("esp32")      >= 0 ||
        s.indexOf("esp8266")    >= 0 ||
        s.indexOf("esp_")       >= 0) { strlcpy(label,"Dispositivo ESP BLE", 48); *isMobile=false; *isIot=true;  *conf=88; return; }

    strlcpy(label, "Dispositivo BLE", 48);
    *isMobile = false; *isIot = false; *conf = 15;
}

// =====================================================
// HELPERS INTERNOS — BLE UUID → flags
// =====================================================

static bool _bleUuidClassify(const char* uuids,
                              char* label, bool* isMobile,
                              bool* isIot)
{
    if (!uuids || uuids[0] == '\0') return false;

    String s = String(uuids);
    s.toUpperCase();

    for (size_t i = 0; i < BLE_SERVICE_TABLE_LEN; i++) {
        if (s.indexOf(BLE_SERVICE_TABLE[i].uuid) >= 0) {
            strlcpy(label, BLE_SERVICE_TABLE[i].tipo, 48);

            String t = String(BLE_SERVICE_TABLE[i].tipo);
            t.toLowerCase();
            *isIot    = (t.indexOf("monitor")   >= 0 ||
                         t.indexOf("sensor")    >= 0 ||
                         t.indexOf("balança")   >= 0 ||
                         t.indexOf("tuya")      >= 0 ||
                         t.indexOf("wled")      >= 0 ||
                         t.indexOf("iot")       >= 0 ||
                         t.indexOf("band")      >= 0 ||
                         t.indexOf("fitness")   >= 0 ||
                         t.indexOf("automação") >= 0);
            *isMobile = (t.indexOf("fone")      >= 0 ||
                         t.indexOf("teclado")   >= 0 ||
                         t.indexOf("mouse")     >= 0 ||
                         t.indexOf("hid")       >= 0 ||
                         t.indexOf("iphone")    >= 0 ||
                         t.indexOf("apple")     >= 0 ||
                         t.indexOf("google")    >= 0 ||
                         t.indexOf("amazon")    >= 0);
            return true;
        }
    }
    return false;
}

// =====================================================
// classifyWiFi
// Entrada: mac (AA:BB:CC:DD:EE:FF), ssid, rssi, canal
// =====================================================

inline DeviceProfile classifyWiFi(const char* mac,
                                   const char* ssid,
                                   int8_t rssi,
                                   int8_t channel)
{
    DeviceProfile prof;
    prof.confidence  = 15;
    prof.is_mobile   = false;
    prof.is_iot      = false;
    prof.is_sensor   = false;
    prof.is_actuator = false;
    strlcpy(prof.vendor,   "Desconhecido", sizeof(prof.vendor));
    strlcpy(prof.label,    "Rede WiFi",    sizeof(prof.label));
    strlcpy(prof.protocol, "WiFi",         sizeof(prof.protocol));

    // 1) OUI
    char ouiFab[28]  = "Desconhecido";
    char ouiTipo[48] = "N/A";
    bool ouiHit = lookupOUI(mac, ouiFab, sizeof(ouiFab),
                                 ouiTipo, sizeof(ouiTipo));

    // 2) SSID heurística
    char ssidLabel[48];
    bool ssidMobile = false, ssidIot = false;
    uint8_t ssidConf = 0;
    _ssidClassify(ssid, ssidLabel, &ssidMobile, &ssidIot, &ssidConf);

    // 3) Flags do OUI
    bool ouiMobile = false, ouiIot = false;
    if (ouiHit) _ouiFlags(ouiTipo, &ouiMobile, &ouiIot);

    // Decisão: SSID confiável > OUI > SSID fraco
    if (ssidConf >= 78) {
        strlcpy(prof.label,  ssidLabel,                         sizeof(prof.label));
        strlcpy(prof.vendor, ouiHit ? ouiFab : "Desconhecido",  sizeof(prof.vendor));
        prof.confidence = ssidConf;
        prof.is_mobile  = ssidMobile;
        prof.is_iot     = ssidIot;
    } else if (ouiHit) {
        strlcpy(prof.vendor, ouiFab,  sizeof(prof.vendor));
        prof.is_mobile  = ouiMobile;
        prof.is_iot     = ouiIot;
        if (ssidConf >= 30) {
            strlcpy(prof.label, ssidLabel, sizeof(prof.label));
            prof.confidence = max(ssidConf, (uint8_t)62);
        } else {
            strlcpy(prof.label, ouiTipo,   sizeof(prof.label));
            prof.confidence = 65;
        }
    } else {
        strlcpy(prof.vendor, "Desconhecido", sizeof(prof.vendor));
        strlcpy(prof.label,  ssidConf > 0 ? ssidLabel : "Rede WiFi", sizeof(prof.label));
        prof.confidence = ssidConf > 0 ? ssidConf : 15;
        prof.is_mobile  = ssidMobile;
        prof.is_iot     = ssidIot;
    }

    // Boost quando OUI e SSID concordam
    if (ouiHit && ssidConf >= 50 &&
        ouiMobile == ssidMobile && ouiIot == ssidIot)
        prof.confidence = (uint8_t)min(99, (int)prof.confidence + 8);

    // Protocolo
    _detectProtocolWiFi(prof.label, prof.vendor, prof.is_iot,
                         prof.protocol, sizeof(prof.protocol));

    // Sensor / Atuador
    _detectSensorActuator(prof.label, &prof.is_sensor, &prof.is_actuator);

    return prof;
}

// =====================================================
// classifyBLE
// Entrada: mac, nome, uuids (ex: "180D,FE95"),
//          macAleatorio, rssi
// =====================================================

inline DeviceProfile classifyBLE(const char* mac,
                                  const char* nome,
                                  const char* uuids,
                                  bool macAleatorio,
                                  int8_t rssi)
{
    DeviceProfile prof;
    prof.confidence  = 15;
    prof.is_mobile   = false;
    prof.is_iot      = false;
    prof.is_sensor   = false;
    prof.is_actuator = false;
    strlcpy(prof.vendor,   "Desconhecido",   sizeof(prof.vendor));
    strlcpy(prof.label,    "Dispositivo BLE",sizeof(prof.label));
    strlcpy(prof.protocol, "BLE",            sizeof(prof.protocol));

    // 1) OUI (só MACs fixos)
    char ouiFab[28]  = "Desconhecido";
    char ouiTipo[48] = "N/A";
    bool ouiHit = false;
    if (!macAleatorio)
        ouiHit = lookupOUI(mac, ouiFab, sizeof(ouiFab),
                                ouiTipo, sizeof(ouiTipo));

    bool ouiMobile = false, ouiIot = false;
    if (ouiHit) _ouiFlags(ouiTipo, &ouiMobile, &ouiIot);

    // 2) Nome
    char nameLabel[48];
    bool nameMobile = false, nameIot = false;
    uint8_t nameConf = 0;
    if (nome && nome[0] != '\0')
        _bleNameClassify(nome, nameLabel, &nameMobile, &nameIot, &nameConf);

    // 3) UUID de serviço
    char uuidLabel[48];
    bool uuidMobile = false, uuidIot = false;
    bool uuidHit = _bleUuidClassify(uuids, uuidLabel, &uuidMobile, &uuidIot);

    // Prioridade: Nome >= 75 > OUI > UUID > nome fraco
    if (nameConf >= 75) {
        strlcpy(prof.label,  nameLabel,                        sizeof(prof.label));
        strlcpy(prof.vendor, ouiHit ? ouiFab : "Desconhecido", sizeof(prof.vendor));
        prof.confidence = nameConf;
        prof.is_mobile  = nameMobile;
        prof.is_iot     = nameIot;
    } else if (ouiHit) {
        strlcpy(prof.vendor, ouiFab, sizeof(prof.vendor));
        if (nameConf > 0) {
            strlcpy(prof.label, nameLabel, sizeof(prof.label));
            prof.confidence = max(nameConf, (uint8_t)62);
            prof.is_mobile  = nameMobile;
            prof.is_iot     = nameIot;
        } else if (uuidHit) {
            strlcpy(prof.label, uuidLabel, sizeof(prof.label));
            prof.confidence = 65;
            prof.is_mobile  = uuidMobile;
            prof.is_iot     = uuidIot;
        } else {
            strlcpy(prof.label, ouiTipo, sizeof(prof.label));
            prof.confidence = 62;
            prof.is_mobile  = ouiMobile;
            prof.is_iot     = ouiIot;
        }
    } else if (uuidHit) {
        strlcpy(prof.vendor, "Desconhecido", sizeof(prof.vendor));
        strlcpy(prof.label,  uuidLabel,      sizeof(prof.label));
        prof.confidence = 60;
        prof.is_mobile  = uuidMobile;
        prof.is_iot     = uuidIot;
    } else if (nameConf > 0) {
        strlcpy(prof.vendor, "Desconhecido", sizeof(prof.vendor));
        strlcpy(prof.label,  nameLabel,      sizeof(prof.label));
        prof.confidence = nameConf;
        prof.is_mobile  = nameMobile;
        prof.is_iot     = nameIot;
    }

    // MAC aleatório sem classificação → provavelmente celular
    if (macAleatorio && prof.confidence < 50) {
        if (strcmp(prof.label, "Dispositivo BLE") == 0)
            strlcpy(prof.label, "Celular/Tablet (MAC aleatório)", sizeof(prof.label));
        prof.is_mobile  = true;
        prof.confidence = max(prof.confidence, (uint8_t)40);
    }

    // Protocolo BLE
    _detectProtocolBLE(prof.label, uuids, prof.is_iot,
                        prof.protocol, sizeof(prof.protocol));

    // Sensor / Atuador
    _detectSensorActuator(prof.label, &prof.is_sensor, &prof.is_actuator);

    return prof;
}
