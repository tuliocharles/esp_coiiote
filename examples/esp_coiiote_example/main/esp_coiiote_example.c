#include <stdio.h>
#include "esp_coiiote.h"
#include "esp_wifi_interface.h"
#include "esp_mqtt_interface.h"

#define LED_STATUS 2
#define LED_RESET 0
#define HOST "coiiote.com" //"192.168.1.12"//

static void evento_mqtt(uint32_t received_id, const char *topic, const char *data)
{

    switch ((esp_mqtt_event_id_t)received_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI("MQTT_EVENT", "Conectado ao broker MQTT");

        char topic_to_subscribe[100];
        snprintf(topic_to_subscribe, sizeof(topic_to_subscribe), "%s/%s/ota",
                 (char *)esp_coiiote_get_workspace(),
                 (char *)esp_coiiote_get_thingname());       // Construct the topic using MAC address, thing name, and workspace
        esp_mqtt_interface_subscribe(topic_to_subscribe, 0); // Inscreve-se no tópico para receber mensagens

        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI("MQTT_EVENT", "Desconectado do broker MQTT");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI("MQTT_EVENT", "Inscrito no tópico: %s", topic);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI("MQTT_EVENT", "Desinscrito do tópico: %s", topic);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI("MQTT_EVENT", "Publicado no tópico: %s", topic);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI("MQTT_EVENT", "Dados recebidos no tópico: %s, Dados: %s", topic, data);

        char otatopic[100];
        snprintf(otatopic, sizeof(otatopic), "%s/%s/ota",
                 (char *)esp_coiiote_get_workspace(),
                 (char *)esp_coiiote_get_thingname()); // Construct the topic using MAC address, thing name, and workspace
        if (strcmp(topic, otatopic) == 0)
        {
            char otadata[100];
            snprintf(otadata, sizeof(otadata), "http://coiiote.com/ota/%s",
                     data); // Construct the topic using MAC address, thing name, and workspace

            // função esp_coiiote para atulizar firmware via OTA
            esp_coiiote_ota(otadata); // Call the function to update firmware via OTA
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE("MQTT_EVENT", "Erro no evento MQTT");
        break;
    default:
        ESP_LOGI("MQTT_EVENT", "Outro evento: %lu", received_id);
    }
}

static void http_test_task(void *pvParameters)
{
    // http_rest_with_hostname_path(); // HTTP REST API example
    esp_coiiote_access(); // Send data to CoIIoTe server

    vTaskDelete(NULL); // Delete the task after completion
}

void app_main(void)
{

    esp_wifi_interface_config_t wifi_inteface_config = {
        .channel = 1,                                               // Access point channel
        .esp_max_retry = 5,                                         // Maximum number of retries to connect to the AP
        .wifi_sae_mode = WPA3_SAE_PWE_BOTH,                         // SAE mode for WPA3
        .esp_wifi_scan_auth_mode_treshold = WIFI_AUTH_WPA_WPA2_PSK, // Authentication mode threshold for Wi-Fi scan
        .status_io = LED_STATUS,                                    // Connection status.
        .reset_io = LED_RESET,                                      // Reset pin.
    };
    WiFiInit(&wifi_inteface_config);
    WiFiSimpleConnection();

    esp_coiiote_config_t coiiote_config = {
        .server = HOST,
        .port = 443,
        .nvs_coiiote_handle = esp_wifi_get_coiiote_nvs_handle(),
    };
    esp_coiiote_init(&coiiote_config);

    esp_mqtt_interface_config_t client_mqtt = {
        .host = HOST,
        .port = 1883,
        .username = esp_coiiote_get_mac_str(),
        .password = (char *)esp_coiiote_get_thing_password(),
        .id = esp_coiiote_get_mac_str(),
    };
    esp_mqtt_interface_init(&client_mqtt);
    esp_mqtt_interface_register_cb(evento_mqtt);
    esp_coiiote_debug();

    xTaskCreate(&http_test_task, "http_test_task", 8192, NULL, 5, NULL);

    uint64_t cont = 0; // Counter for the number of messages sent

            while (1)
    {

        vTaskDelay(1000 / portTICK_PERIOD_MS);
        esp_wifi_check_reset_button();

        cont++;
        char topic[100];
        snprintf(topic, sizeof(topic), "%s/%s/Time",
                 (char *)esp_coiiote_get_workspace(),
                 (char *)esp_coiiote_get_thingname()); // Construct the topic using MAC address, thing name, and workspace
        char data[50];
        snprintf(data, sizeof(data), "%llu seconds", cont);
        //esp_mqtt_interface_publish(topic, data, 0, 0);
    }
}
