/* Copyright 2018 Paul Stoffregen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <Arduino.h>
#include <fnet.h>
#include "NativeEthernet.h"
#include "utility/w5100.h"
#include "NativeDhcp.h"

IPAddress EthernetClass::_dnsServerAddress;
DhcpClass* EthernetClass::_dhcp = NULL;
DMAMEM uint8_t EthernetClass::stack_heap[64u * 1024u]; //Buffer for stack usage, each service has it's own
IntervalTimer EthernetClass::_fnet_poll;
volatile boolean EthernetClass::link_status = 0;
DMAMEM uint8_t EthernetClass::socket_buf_receive[MAX_SOCK_NUM][FNET_SOCKET_DEFAULT_SIZE];
DMAMEM uint16_t EthernetClass::socket_buf_index[MAX_SOCK_NUM];
DMAMEM uint8_t EthernetClass::socket_buf_transmit[MAX_SOCK_NUM][FNET_SOCKET_DEFAULT_SIZE];
DMAMEM uint16_t EthernetClass::socket_buf_len[MAX_SOCK_NUM];
DMAMEM uint16_t EthernetClass::socket_port[MAX_SOCK_NUM];
DMAMEM uint8_t* EthernetClass::socket_addr[MAX_SOCK_NUM];
volatile fnet_socket_t EthernetClass::socket_ptr[MAX_SOCK_NUM] = {nullptr};

int EthernetClass::begin(uint8_t *mac, unsigned long timeout, unsigned long responseTimeout)
{
    unsigned long startMillis = millis();
    if(!fnet_netif_is_initialized(fnet_netif_get_default())){
        struct fnet_init_params     init_params;
    
        static const fnet_mutex_api_t teensy_mutex_api = {
            .mutex_init = teensy_mutex_init,
            .mutex_release = teensy_mutex_release,
            .mutex_lock = teensy_mutex_lock,
            .mutex_unlock = teensy_mutex_unlock,
        };
        static const fnet_timer_api_t timer_api = { //Setup millis timer
          .timer_get_ms = timer_get_ms,
          .timer_delay = 0,
        };
        /* Input parameters for FNET stack initialization */
        init_params.netheap_ptr = stack_heap;
        init_params.netheap_size = sizeof(stack_heap);
        init_params.mutex_api = &teensy_mutex_api;
        init_params.timer_api = &timer_api;
        /* FNET Initialization */
        if (fnet_init(&init_params) != FNET_ERR) {
//          Serial.println("TCP/IP stack initialization is done.\n");
          /* You may use FNET stack API */
          /* Initialize networking interfaces using fnet_netif_init(). */
    //        Get current net interface.
          if(fnet_netif_init(FNET_CPU_ETH0_IF, mac, 6) != FNET_ERR){
//            Serial.println("netif Initialized");
            if(fnet_netif_get_default() == 0){
//              Serial.println("ERROR: Network Interface is not configurated!");
              return false;
            }
            else {
//              Serial.println("SUCCESS: Network Interface is configurated!");
              fnet_link_params_t link_params;
              link_params.netif_desc = fnet_netif_get_default();
              link_params.callback = link_callback;
              static unsigned long _responseTimeout = responseTimeout;
              link_params.callback_param = &_responseTimeout;
              fnet_link_init(&link_params);
              _fnet_poll.begin(fnet_poll, FNET_POLL_TIME);
            }
          }
          else {
//            Serial.println("Error:netif initialization failed.\n");
            return false;
          }
        }
        else {
//          Serial.println("Error:TCP/IP stack initialization failed.\n");
          return false;
        }
    }
    else{
//        Serial.println("Error:TCP/IP stack already initialized.");
        return true;
    }
    
    while(!fnet_dhcp_cln_is_enabled(fnet_dhcp_cln_get_by_netif(fnet_netif_get_default()))){
        //Wait for dhcp initialization
        if(millis() >= startMillis + timeout) return false;
    }
    
    struct fnet_dhcp_cln_options current_options;
    do {//Wait for IP Address
        fnet_dhcp_cln_get_options(fnet_dhcp_cln_get_by_netif(fnet_netif_get_default()), &current_options);
    } while (!current_options.ip_address.s_addr);
    
    return true;
}

void EthernetClass::begin(uint8_t *mac, IPAddress ip)
{
	// Assume the DNS server will be the machine on the same network as the local IP
	// but with last octet being '1'
	IPAddress dns = ip;
	dns[3] = 1;
	begin(mac, ip, dns);
}

void EthernetClass::begin(uint8_t *mac, IPAddress ip, IPAddress dns)
{
	// Assume the gateway will be the machine on the same network as the local IP
	// but with last octet being '1'
	IPAddress gateway = ip;
	gateway[3] = 1;
	begin(mac, ip, dns, gateway);
}

void EthernetClass::begin(uint8_t *mac, IPAddress ip, IPAddress dns, IPAddress gateway)
{
	IPAddress subnet(255, 255, 255, 0);
	begin(mac, ip, dns, gateway, subnet);
}

void EthernetClass::begin(uint8_t *mac, IPAddress ip, IPAddress dns, IPAddress gateway, IPAddress subnet)
{
    if(!fnet_netif_is_initialized(fnet_netif_get_default())){
        struct fnet_init_params     init_params;
    
        static const fnet_mutex_api_t teensy_mutex_api = {
            .mutex_init = teensy_mutex_init,
            .mutex_release = teensy_mutex_release,
            .mutex_lock = teensy_mutex_lock,
            .mutex_unlock = teensy_mutex_unlock,
        };
        static const fnet_timer_api_t timer_api = { //Setup millis timer
          .timer_get_ms = timer_get_ms,
          .timer_delay = 0,
        };
        /* Input parameters for FNET stack initialization */
        init_params.netheap_ptr = stack_heap;
        init_params.netheap_size = sizeof(stack_heap);
        init_params.mutex_api = &teensy_mutex_api;
        init_params.timer_api = &timer_api;
        /* FNET Initialization */
        if (fnet_init(&init_params) != FNET_ERR) {
//          Serial.println("TCP/IP stack initialization is done.\n");
          /* You may use FNET stack API */
          /* Initialize networking interfaces using fnet_netif_init(). */
    //        Get current net interface.
          if(fnet_netif_init(FNET_CPU_ETH0_IF, mac, 6) != FNET_ERR){
//            Serial.println("netif Initialized");
            if(fnet_netif_get_default() == 0){
//              Serial.println("ERROR: Network Interface is not configurated!");
              return;
            }
            else {
//              Serial.println("SUCCESS: Network Interface is configurated!");
              fnet_link_params_t link_params;
              link_params.netif_desc = fnet_netif_get_default();
              link_params.callback = link_callback;
              fnet_link_init(&link_params);
              _fnet_poll.begin(fnet_poll, FNET_POLL_TIME);
            }
          }
          else {
//            Serial.println("Error:netif initialization failed.\n");
            return;
          }
        }
        else {
//          Serial.println("Error:TCP/IP stack initialization failed.\n");
          return;
        }
    }
    else{
//        Serial.println("Error:TCP/IP stack already initialized.");
        return;
    }
    
    fnet_netif_set_ip4_addr(fnet_netif_get_default(), ip, subnet);
    fnet_netif_set_ip4_gateway(fnet_netif_get_default(), gateway);
    fnet_netif_set_ip4_dns(fnet_netif_get_default(), dns);
    
    while(!link_status){
    }
    
    
}

void EthernetClass::init(uint8_t sspin)
{
	
}

EthernetLinkStatus EthernetClass::linkStatus()
{
	switch ((uint8_t)link_status) {
		case 0:  return LinkOFF;
		case 1: return LinkON;
		default:       return Unknown;
	}
}

EthernetHardwareStatus EthernetClass::hardwareStatus()
{
    return EthernetW5500;
}

int EthernetClass::maintain()
{
	return 0; //DHCP already maintained
}


void EthernetClass::MACAddress(uint8_t *mac_address)
{
    fnet_netif_get_hw_addr(fnet_netif_get_default(), mac_address, 6);
}

IPAddress EthernetClass::localIP()
{
	return IPAddress(fnet_netif_get_ip4_addr(fnet_netif_get_default()));
}

IPAddress EthernetClass::subnetMask()
{
	return IPAddress(fnet_netif_get_ip4_subnet_mask(fnet_netif_get_default()));
}

IPAddress EthernetClass::gatewayIP()
{
	return IPAddress(fnet_netif_get_ip4_gateway(fnet_netif_get_default()));
}

void EthernetClass::setMACAddress(const uint8_t *mac_address)
{
	fnet_netif_set_hw_addr(fnet_netif_get_default(), (fnet_uint8_t*)mac_address, 6);
}

void EthernetClass::setLocalIP(const IPAddress local_ip)
{
    fnet_netif_set_ip4_addr(fnet_netif_get_default(), *const_cast<IPAddress*>(&local_ip), subnetMask());
}

void EthernetClass::setSubnetMask(const IPAddress subnet)
{
	fnet_netif_set_ip4_addr(fnet_netif_get_default(), localIP(), *const_cast<IPAddress*>(&subnet));
}

void EthernetClass::setGatewayIP(const IPAddress gateway)
{
	fnet_netif_set_ip4_gateway(fnet_netif_get_default(), *const_cast<IPAddress*>(&gateway));
}

void EthernetClass::setDnsServerIP(const IPAddress dns_server)
{
    fnet_netif_set_ip4_dns(fnet_netif_get_default(), *const_cast<IPAddress*>(&dns_server));
}

void EthernetClass::setRetransmissionTimeout(uint16_t milliseconds)
{
	//Not needed, probably
}

void EthernetClass::setRetransmissionCount(uint8_t num)
{
	//Not needed, probably
}



fnet_return_t EthernetClass::teensy_mutex_init(fnet_mutex_t *mutex) {
  return FNET_OK;
}

void EthernetClass::teensy_mutex_release(fnet_mutex_t *mutex) {
}

void EthernetClass::teensy_mutex_lock(fnet_mutex_t *mutex) {
}

void EthernetClass::teensy_mutex_unlock(fnet_mutex_t *mutex) {
}

fnet_time_t EthernetClass::timer_get_ms(void){ //Used for multi-thread version
    fnet_time_t result;
    result =  millis();
    return result;
}

void EthernetClass::link_callback(fnet_netif_desc_t netif, fnet_bool_t connected, void *callback_param){
//  Serial.println(connected ? "Link Connected!" : "Link Disconnected!");
  link_status = connected;
  if(connected){
//    Serial.println("Initialising Services!");
//    init_services(netif);
    if(localIP() == IPAddress(0,0,0,0)){
//       Serial.println("Initializing DHCP");
    
       static fnet_dhcp_cln_params_t dhcp_params; //DHCP intialization parameters
       dhcp_params.netif = netif;
       // Enable DHCP client.
       if(fnet_dhcp_cln_init(&dhcp_params)){
         fnet_dhcp_cln_set_response_timeout(fnet_dhcp_cln_get_by_netif(netif), *(unsigned long*)callback_param);
           /*Register DHCP event handler callbacks.*/
//          fnet_dhcp_cln_set_callback_updated(fnet_dhcp_cln_get_by_netif(netif), dhcp_cln_callback_updated, NULL);
//          fnet_dhcp_cln_set_callback_discover(fnet_dhcp_cln_get_by_netif(netif), dhcp_cln_callback_updated, NULL);
//         Serial.println("DHCP initialization done!");
       }
       else{
//         Serial.println("ERROR: DHCP initialization failed!");
       }
    }
      
  }
  else{
//    Serial.println("Releasing Services!");
//    release_services(netif);
    fnet_dhcp_cln_release(fnet_dhcp_cln_get_by_netif(netif));
  }
}

void EthernetClass::dhcp_cln_callback_updated(fnet_dhcp_cln_desc_t _dhcp_desc, fnet_netif_desc_t netif, void *p) { //Called when DHCP updates
  struct fnet_dhcp_cln_options current_options;
  fnet_dhcp_cln_get_options(_dhcp_desc, &current_options);
  
  uint8_t *ip = (uint8_t*)&current_options.ip_address.s_addr;
  Serial.print("IPAddress: ");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.println((uint8_t)*ip);

  ip = (uint8_t*)&current_options.netmask.s_addr;
  Serial.print("SubnetMask: ");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.println((uint8_t)*ip);

  ip = (uint8_t*)&current_options.gateway.s_addr;
  Serial.print("Gateway: ");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.println((uint8_t)*ip);

  ip = (uint8_t*)&current_options.dhcp_server.s_addr;
  Serial.print("DHCPServer: ");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.print((uint8_t)*ip++);
  Serial.print(".");
  Serial.println((uint8_t)*ip);

  
  Serial.print("State: ");
  Serial.println(fnet_dhcp_cln_get_state(_dhcp_desc));
  Serial.println();
  Serial.println();

  

}




EthernetClass Ethernet;
