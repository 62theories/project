// This software is licensed under the MIT License.
// See the license file for details.
// For more details visit github.com/spacehuhn/DeauthDetector

// include necessary libraries
#include <ESP8266WiFi.h>



// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}

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

struct List{
byte* addr_a;
int packet_count;
List* next;
};
List* Head = NULL;

void insert(byte* addr_a,int packet_count)
{
  List **ptrTohead = &Head;
  if(*ptrTohead == NULL)
  {
    *ptrTohead = (List*)malloc(sizeof(List));
    (*ptrTohead)->addr_a = addr_a;
    (*ptrTohead)->packet_count = packet_count;
    (*ptrTohead)->next = NULL;
  }
  else
  {
    List* newnode = (List*)malloc(sizeof(List));
    (newnode)->addr_a = addr_a;
    (newnode)->packet_count = packet_count;

    newnode->next = *ptrTohead;
    *ptrTohead = newnode;       
  }
}

List* find(byte* addr_a)
{

  List *ptr = Head;
  while(ptr!=NULL)
  {
    if(ptr->addr_a == addr_a)
    {
      return ptr;
    }
    else
    {
      ptr = ptr->next;
    }
  }
  return NULL;

  
}

// ===== Sniffer function ===== //
void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return; // Drop packets without MAC header

  byte pkt_type = buf[12]; // second half of frame control field
  byte* addr_a = &buf[16]; // first MAC address
  //byte* addr_b = &buf[22]; // second MAC address

  // If captured packet is a deauthentication or dissassociaten frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {

    
  List *ptr = find(addr_a);
      if ( ptr != NULL )
      {

        ptr->packet_count++;
              
      }
      else
      {

        insert(addr_a,1);
        
      }
     
     


    
    
  }
}

// ===== Attack detection functions ===== //
void attack_started() {
  digitalWrite(LED, !LED_INVERT); // turn LED on
  Serial.println("ATTACK DETECTED");
}

void attack_stopped() {
  digitalWrite(LED, LED_INVERT); // turn LED off
  Serial.println("RESET");
}

// ===== Setup ===== //
void setup() {
  Serial.begin(SERIAL_BAUD); // Start serial communication

  pinMode(LED, OUTPUT); // Enable LED pin
  digitalWrite(LED, LED_INVERT);

  WiFi.disconnect();                   // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);       // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer); // Set sniffer function
  wifi_set_channel(channels[0]);        // Set channel
  wifi_promiscuous_enable(true);       // Enable sniffer

  //Serial.println("Started \\o/");
  
}



// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis(); // Get current time (in ms)
  
  
  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels)*CH_TIME)) {
    update_time = current_time; // Update time variable

    
    // When detected deauth packets exceed the minimum allowed number
    List* ptr = Head;
    List* temp;
    if(period >= 10)
    {
      ptr = Head;
      while(ptr != NULL)
      {
    
      ptr->packet_count = 0;
    
      ptr = ptr->next;
      
      }
      attack_stopped();
      Serial.print("reset\n");
      period = 0;
    }
    else
    {
      ptr = Head;
      while(ptr != NULL)
      {
    
      if (ptr->packet_count >= 5) {
      attack_started(); // Increment attack counter
      }
      Serial.print("in loop\n");
    
      ptr = ptr->next;
      }  
    }
    period++;
    
    
  }

  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time; // Update time variable

    // Get next channel
    ch_index = (ch_index+1) % (sizeof(channels)/sizeof(channels[0]));
    short ch = channels[ch_index];

    // Set channel
    //Serial.print("Set channel to ");
    //Serial.println(ch);
    wifi_set_channel(ch);
  }

}
