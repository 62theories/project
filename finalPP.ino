#include <WiFi.h>
#include <map>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
//WiFi
// include Non-OS SDK functions
#include "esp_wifi.h"
const wifi_promiscuous_filter_t filt={
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};
typedef struct {
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct {
  int16_t fctl;
  int16_t duration;
  MacAddr da;
  MacAddr sa;
  MacAddr bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;



// ===== SETTINGS ===== //
#define LED 2              /* LED pin (2=built-in LED) */
#define LED_INVERT true    /* Invert HIGH/LOW for LED */
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 5         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13/*,14*/ };

// ===== Runtime variables ===== //
int ch_index { 0 };               // Current index of channel array
int packet_rate { 0 };            // Deauth packet counter (resets with each update)
int attack_counter { 0 };         // Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time
int period = 0;
bool found = false;
bool configDone = false;

// variables added for training experiment
bool trainingend = false;
int count = 0;
int deauthCountMax = 0;
int probeCountMax = 0;
int beaconCountMax = 0;
int temp1,temp2,temp3;

//
std::map<uint8_t*,int> memforbeacon;
std::map<uint8_t*,int> memfordeauth;
std::map<uint8_t*,int> memforprobe;
std::map<uint8_t*,int>::iterator it;

// ===== Sniffer function ===== //
void sniffer(void* buff, wifi_promiscuous_pkt_type_t type) {
  //Serial.println("packet incoming");
  std::map<uint8_t*,int> ::iterator itrfordeauth;
  std::map<uint8_t*,int> ::iterator itrforbeacon;
  std::map<uint8_t*,int> ::iterator itrforprobe;
   if (type == WIFI_PKT_MGMT) {
 // Serial.println("packet caught");
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buff;
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
  len -= sizeof(WifiMgmtHdr);
  if (len < 0) return;
  int fctl = ntohs(wh->fctl);
  
//  byte pkt_type = buf[12]; // second half of frame control field
//  byte* addr_a = &buf[16]; // first MAC address
//  byte* addr_b = &buf[22]; // second MAC address

  // If captured packet is a deauthentication or dissassociaten frame
//  
  MacAddr addr_aa = (wh->da);
  byte* addr_a =  addr_aa.mac;
  MacAddr addr_bb = (wh->sa);
  byte* addr_b =  addr_bb.mac;
// Serial.println(fctl,HEX);
//
if (fctl == 0x0A000 || fctl == 0x0C000) {  
//  Serial.println("DEAUTH");
  itrfordeauth = memfordeauth.find(addr_a); 
  if(itrfordeauth == memfordeauth.end())
  {
    memfordeauth[addr_a] = 1;
  }
  else
  {
    temp1 = (int)(itrfordeauth->second+1);
    memfordeauth[addr_a] = itrfordeauth->second+1;
    if(configDone == true && trainingend == false)
    {
      if(temp1 > deauthCountMax)
      {
        deauthCountMax = temp1; 
      }
    }
    else if(configDone == true && trainingend == true)
    {
      if(temp1 > deauthCountMax)
      {
        found = true;
        Serial.println("Alert now deauth =");
        Serial.println(temp1);
      }
    }
  }





 
  }
  if (fctl == 0x08000) {  
    itrforbeacon = memforbeacon.find(addr_b); 
    if(itrforbeacon == memforbeacon.end())
    {
      memforbeacon[addr_b] = 1;
    }
    else
    {
      temp2 = (int)(itrforbeacon->second+1);
      memforbeacon[addr_b] = itrforbeacon->second+1;

      if(configDone == true && trainingend == false)
    {
      if(temp2 > beaconCountMax)
      {
        beaconCountMax = temp2; 
      }
    }
    else if(configDone == true && trainingend == true)
    {
      if(temp2 > beaconCountMax * 5)
      {
        found = true;
        Serial.println("Alert now beacon =");
        Serial.println(temp2);
      }
    }
    }
  }
  if (fctl == 0x04000 ) {  
  
    itrforprobe = memforprobe.find(addr_a); 
    if(itrforprobe == memforprobe.end())
    {
      memforprobe[addr_a] = 1;
    }
    else
    {
      temp3 = (int)(itrforprobe->second+1);
      memforprobe[addr_a] = itrforprobe->second+1;
      if(configDone == true && trainingend == false)
    {
      if(temp3 > probeCountMax)
      {
        probeCountMax = temp3; 
      }
    }
    else if(configDone == true && trainingend == true)
    {
      if(temp3 > probeCountMax * 2)
      {
        found = true;
        Serial.println("Alert now probe =");
        Serial.println(temp3);
      }
    }
    }
  }

  



  
  
  
  
}
}






//BLUETOOTH
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
int dat;
class CallBackFunction1: public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic){
    std::string rxValue = pCharacteristic->getValue();

    if(rxValue.length()>0 && configDone == false)
    {
      Serial.println("Start recieving");
      Serial.println("recieved:");

       for(int i=0;i<rxValue.length();i++){
        dat = (int)rxValue[i];
        Serial.println((int)rxValue[i]);
       }

       if(dat == 4){
        Serial.println("Start training");
        configDone = true;
        dat = 0;
       }
       else
       {
        deauthCountMax = (int)rxValue[0];
        beaconCountMax = (int)rxValue[1];
        probeCountMax = (int)rxValue[2];
        Serial.print("set deauth: ");
        Serial.println(deauthCountMax);
        Serial.print("set beacon: ");
        Serial.println(beaconCountMax);
        Serial.print("set probe: ");
        Serial.println(probeCountMax);
        trainingend = true;
        configDone = true;
       }
        
       
       
        Serial.println(dat);
        Serial.println("End recieving");
    }
  }
};
// ===== Setup ===== //
void setup() {

  Serial.begin(SERIAL_BAUD); // Start serial communication
  pinMode(LED, OUTPUT); // Enable LED pin
  digitalWrite(LED, LOW);
  Serial.begin(115200);
  BLEDevice::init("Long name works now");
  BLEServer *pServer = BLEDevice::createServer();
  BLEService *pService = pServer->createService(SERVICE_UUID);
  BLECharacteristic *pCharacteristic = pService->createCharacteristic(
                                         CHARACTERISTIC_UUID,
                                         BLECharacteristic::PROPERTY_READ |
                                         BLECharacteristic::PROPERTY_WRITE
                                       );

  //pCharacteristic->setValue("Hello World says Neil");
  pCharacteristic->setCallbacks(new CallBackFunction1());
  pService->start();
  // BLEAdvertising *pAdvertising = pServer->getAdvertising();  // this still is working for backward compatibility
  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);  // functions that help with iPhone connections issue
  pAdvertising->setMinPreferred(0x12);
  BLEDevice::startAdvertising();
  Serial.println("Characteristic defined! Now you can read it in your phone!");
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(channels[0], WIFI_SECOND_CHAN_NONE);
  Serial.println("Started \\o/");
}




// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis(); // Get current time (in ms)
  
  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels)*CH_TIME)) { 
    update_time = current_time; // Update time variable
    if(configDone == false)
    {
      Serial.println("waiting");
    }
    
    //****When detected deauth packets exceed the minimum allowed number*****

    if(configDone == true && trainingend == false)
    {
      count++;
      Serial.println("count=");
      Serial.println(count);
      Serial.println("deauthMax=");
      Serial.println(deauthCountMax);
      Serial.println("beaconMax=");
      Serial.println(beaconCountMax);
      Serial.println("probeMax=");
      Serial.println(probeCountMax);
      memforbeacon.clear();
    memfordeauth.clear();
      memforprobe.clear();
      if(count == 10)
      {
        if(deauthCountMax < 10)
        {
          deauthCountMax = 10;
        }
        if(beaconCountMax < 50)
        {
          beaconCountMax = 50;
        }
        if(probeCountMax < 30)
        {
          probeCountMax = 30;
        }
        trainingend = true;
      }
    }
    else if(trainingend == true)
    {
      if(period >= 5)
      {
        if(found == true)
        {
          Serial.println("found");
        }
        else
        {
          Serial.println("not found");
        }

        memforbeacon.clear();
        memfordeauth.clear();
        memforprobe.clear();
        found = false;
        period = 0;
     }
     
     period++;
    
    
  }
  }
    
    //****When detected deauth packets exceed the minimum allowed number*****

  //**************Channel hopping************************************
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time; // Update time variable

    // Get next channel
    ch_index = (ch_index+1) % (sizeof(channels)/sizeof(channels[0]));
    short ch = channels[ch_index];

    // Set channel
    //Serial.print("Set channel to ");
    //Serial.println(ch);
//    wifi_set_channel(ch);
     esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  }

  
}
