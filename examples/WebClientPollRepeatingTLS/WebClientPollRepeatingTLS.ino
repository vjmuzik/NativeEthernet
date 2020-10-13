#include <NativeEthernet.h>

// assign a MAC address for the ethernet controller.
// fill in your address here:
uint8_t mac[6];
void teensyMAC(uint8_t *mac) {
    for(uint8_t by=0; by<2; by++) mac[by]=(HW_OCOTP_MAC1 >> ((1-by)*8)) & 0xFF;
    for(uint8_t by=0; by<4; by++) mac[by+2]=(HW_OCOTP_MAC0 >> ((3-by)*8)) & 0xFF;
    Serial.printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// initialize the library instance:
EthernetClient client;

char server[] = "pjrc.com";  // also change the Host line in httpRequest()

unsigned long lastConnectionTime = 0;           // last time you connected to the server, in milliseconds
const unsigned long postingInterval = 10*1000;  // delay between updates, in milliseconds

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  teensyMAC(mac);
  // start serial port:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // start the Ethernet connection:
  Serial.println("Initialize Ethernet with DHCP:");
  if (Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    // Check for Ethernet hardware present
    if (Ethernet.hardwareStatus() == EthernetNoHardware) {
      Serial.println("Ethernet shield was not found.  Sorry, can't run without hardware. :(");
      while (true) {
        delay(1); // do nothing, no point running without Ethernet hardware
      }
    }
    if (Ethernet.linkStatus() == LinkOFF) {
      Serial.println("Ethernet cable is not connected.");
    }
    // try to congifure using IP address instead of DHCP:
  } else {
    Serial.print("  DHCP assigned IP ");
    Serial.println(Ethernet.localIP());
  }
  client.connectPoll(true); //Activate non-blocking client connect
  delay(1000);
}

elapsedMillis led_timer = 0;
void loop() {
  if(led_timer >= 500){
    led_timer -= 500;
    digitalToggle(LED_BUILTIN);
  }
  // if there's incoming data from the net connection.
  // send it out the serial port.  This is for debugging
  // purposes only:
  if (client.available()) {
    char c = client.read();
    Serial.write(c);
  }

  // if ten seconds have passed since your last connection,
  // then connect again and send data:
  if (millis() - lastConnectionTime > postingInterval) {
    httpRequest();
  }

}

// this method makes a HTTP connection to the server:
void httpRequest() {
  static uint32_t start = millis();
  static uint32_t timeout = 10000;

  // close any connection before send a new request.
  if(!client.connected()){
    client.stop();
//    client.connect(server, 80);              //Uncomment for unencrypted connection
    client.connect(server, 443, true);       //Uncomment for encrypted connection
    start = millis();
  }
  
  // if there's a successful connection:
  if (client.connectPoll()) {
    Serial.println("connecting...");
    // send the HTTP GET request:
    client.println("GET / HTTP/1.1");
    client.println("Host: www.pjrc.com");
    client.println("User-Agent: arduino-ethernet");
    client.println("Connection: close");
    client.println();
    client.close(); //If "Connection: close" make sure to close after printing and before stop to avoid harsh reset

    // note the time that the connection was made:
    lastConnectionTime = millis();
  }
  else{
    if (millis() - start > timeout) {
      client.stop();
      Serial.println("Could not connect to client!");
    }
  }
}
