#include <stdio.h>
#include "esp_coiiote.h"
#include "esp_wifi_interface.h"

#define LED_STATUS 2 // GPIO pin for status LED
#define LED_RESET 0 // GPIO pin for reset


static void http_test_task(void *pvParameters)
{
    //http_rest_with_hostname_path(); // HTTP REST API example
    esp_coiiote_access(); // Send data to CoIIoTe server
    
    vTaskDelete(NULL); // Delete the task after completion
}


void app_main(void)
{

    // connect to wi-fi network using esp_wifi_interface
    esp_wifi_interface_config_t wifi_inteface_config = {
        .channel = 1, // Access point channel
        .esp_max_retry = 5, // Maximum number of retries to connect to the AP         
        .wifi_sae_mode = WPA3_SAE_PWE_BOTH, // SAE mode for WPA3
        .esp_wifi_scan_auth_mode_treshold = WIFI_AUTH_WPA_WPA2_PSK, // Authentication mode threshold for Wi-Fi scan
        .status_io = LED_STATUS,  // Connection status. 
        .reset_io = LED_RESET,           // Reset pin.
    };
    
    WiFiInit (&wifi_inteface_config);

    WiFiSimpleConnection();

    // connect to coiiote server
    esp_coiiote_config_t coiiote_config = {
        .server = "coiiote.com", //"192.168.1.12", // Coiiote server address
        .port = 80, //3000, // Coiiote server port
        .nvs_coiiote_handle = esp_wifi_get_coiiote_nvs_handle(), // Coiiote handle
    };

    esp_coiiote_init(&coiiote_config); // Initialize Coiiote
    
    // trazer o outro exemplo pra cá.
        
    // create or log in to coiiote account

    // connect to coiiote mqtt broker

    // starts to send and receive data to and from coiiote
    func();

    esp_coiiote_debug(); // Debugging function to check the status of the coiiote connection

    xTaskCreate(&http_test_task, "http_test_task", 8192, NULL, 5, NULL);

    while(1){
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        esp_wifi_check_reset_button();
        
    }

}
