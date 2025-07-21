#ifndef _esp_coiiote_H_
#define _esp_coiiote_H_


#include "esp_check.h"
#include "esp_nvs.h"


typedef struct esp_coiiote_t *esp_coiiote_handle_t;

typedef struct esp_coiiote_config_t
{
    uint8_t server[64]; // Coiiote server address
    uint32_t port; // Coiiote server port
    esp_nvs_handle_t nvs_coiiote_handle; // Coiiote handle
} esp_coiiote_config_t;

esp_err_t esp_coiiote_init(esp_coiiote_config_t *config);

void esp_coiiote_debug();

void http_rest_with_hostname_path(void);

void esp_coiiote_access(void); // Send data to CoIIoTe server

char* esp_coiiote_get_mac_str(void);

uint8_t* esp_coiiote_get_thing_password(void);

uint8_t* esp_coiiote_get_workspace(void);

uint8_t* esp_coiiote_get_thingname(void);

void esp_coiiote_ota(const char *url);

void esp_coiiote_webserver_init();

#endif