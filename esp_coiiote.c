#include <stdio.h>
#include "esp_coiiote.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_nvs.h"
#include "driver/gpio.h"
// incluir biblioteca para mcopy
#include <string.h>

#include "esp_http_client.h"
#include <sys/param.h>
#include "esp_tls.h"


//#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048


typedef struct esp_coiiote_t esp_coiiote_t;

struct esp_coiiote_t
{
    esp_nvs_handle_t nvs_coiiote_handle; // NVS handle for CoIIoTe
    uint8_t server[64]; // Coiiote server address
    uint32_t port; // Coiiote server port
    char mac_str[13]; // MAC address
    uint8_t thingid[64]; // Coiiote client ID
    uint8_t thingpassword[64]; // Coiiote username
    uint8_t thingname[64]; // Coiiote password
    uint8_t workspace[64]; // Coiiote workspace
    gpio_num_t status_io;
    gpio_num_t reset_io;
};

static esp_coiiote_handle_t esp_coiite_handle = NULL;
static const char *tag_coiiote = "coiiote";

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;  // Buffer to store response of http request from event handler
    static int output_len;       // Stores number of bytes read
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Clean the buffer in case of a new request
            if (output_len == 0 && evt->user_data) {
                // we are just starting to copy the output data into the use
                memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
            }
            /*
             *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
             *  However, event handler can also be used in case chunked encoding is used.
             */
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                int copy_len = 0;
                if (evt->user_data) {
                    // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                    copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                    if (copy_len) {
                        memcpy(evt->user_data + output_len, evt->data, copy_len);
                    }
                } else {
                    int content_len = esp_http_client_get_content_length(evt->client);
                    if (output_buffer == NULL) {
                        // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                        output_buffer = (char *) calloc(content_len + 1, sizeof(char));
                        output_len = 0;
                        if (output_buffer == NULL) {
                            ESP_LOGE(tag_coiiote, "Failed to allocate memory for output buffer");
                            return ESP_FAIL;
                        }
                    }
                    copy_len = MIN(evt->data_len, (content_len - output_len));
                    if (copy_len) {
                        memcpy(output_buffer + output_len, evt->data, copy_len);
                    }
                }
                output_len += copy_len;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
#if CONFIG_EXAMPLE_ENABLE_RESPONSE_BUFFER_DUMP
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
#endif
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(tag_coiiote, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGI(tag_coiiote, "Last esp error code: 0x%x", err);
                ESP_LOGI(tag_coiiote, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(tag_coiiote, "HTTP_EVENT_REDIRECT");
            esp_http_client_set_header(evt->client, "From", "user@example.com");
            esp_http_client_set_header(evt->client, "Accept", "text/html");
            esp_http_client_set_redirection(evt->client);
            break;
    }
    return ESP_OK;
}

static char* mac_bytes_to_hexstr(const uint8_t mac[6], char out_str[13])
{
    for (int i = 0; i < 6; ++i) {
        // Escreve dois dígitos hex em uppercase sem separador
        sprintf(out_str + i * 2, "%02X", mac[i]);
    }
    out_str[12] = '\0';  // null-terminator
    return out_str;
}

static void get_mac_adress(void)
{
    uint8_t mac[6]; // MAC address
    esp_err_t ret;

    ret = esp_read_mac(mac, ESP_MAC_EFUSE_FACTORY);
    if (ret != ESP_OK) {
        ESP_LOGW(tag_coiiote, "Erro ao ler MAC de fábrica: %s\n", esp_err_to_name(ret));
        return;
    }

    // Exibe em formato hexadecimal
    ESP_LOGI(tag_coiiote, "MAC de fábrica (EFUSE_FACTORY): %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Converte para string hexadecimal
    char mac_str[13]; // 6 bytes * 2 hex digits + 1 null terminator
    mac_bytes_to_hexstr(mac, esp_coiite_handle->mac_str);
    ESP_LOGI(tag_coiiote, "MAC de fábrica (EFUSE_FACTORY) em string: %s\n", mac_str);
}

esp_err_t esp_coiiote_init(esp_coiiote_config_t *config)
{
    esp_err_t ret = ESP_OK;
    esp_coiiote_t *esp_coiiote = NULL;
    ESP_GOTO_ON_FALSE(config, ESP_ERR_INVALID_ARG, err, tag_coiiote, "Invalid arguments");
    esp_coiiote = calloc(1, sizeof(esp_coiiote_t));
      
    if (esp_coiiote == NULL) {
        ESP_LOGE(tag_coiiote, "Erro ao alocar memória para esp_coiite_handle\n");
        return ESP_ERR_NO_MEM;
    }

    // copia os parâmetros de configuração
    memcpy(esp_coiiote->server, config->server, sizeof(esp_coiiote->server));
    esp_coiiote->port = config->port;

    esp_coiiote->nvs_coiiote_handle = config->nvs_coiiote_handle;
    //ESP_GOTO_ON_ERROR(esp_coiiote->nvs_coiiote_handle, err, tag_coiiote, "Error to get NVS handle");

    char *generic_p = NULL;
    esp_nvs_change_key("thingid", esp_coiiote->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote->nvs_coiiote_handle, &generic_p) != ESP_OK)
        {
            ESP_LOGE(tag_coiiote, "Error to read Password");
        }
    memcpy(esp_coiiote->thingid, generic_p, strlen(generic_p) + 1);

    esp_nvs_change_key("thingpassword", esp_coiiote->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote->nvs_coiiote_handle, &generic_p) != ESP_OK)
        {
            ESP_LOGE(tag_coiiote, "Error to read Password");
        }
    memcpy(esp_coiiote->thingpassword, generic_p, strlen(generic_p) + 1);

    esp_nvs_change_key("thingname", esp_coiiote->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote->nvs_coiiote_handle, &generic_p) != ESP_OK)
        {
            ESP_LOGE(tag_coiiote, "Error to read Password");
        }
    memcpy(esp_coiiote->thingname, generic_p, strlen(generic_p) + 1);

    esp_nvs_change_key("workspace", esp_coiiote->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote->nvs_coiiote_handle, &generic_p) != ESP_OK)
        {
            ESP_LOGE(tag_coiiote, "Error to read Password");
        }
    memcpy(esp_coiiote->workspace, generic_p, strlen(generic_p) + 1);
    
    
    esp_coiite_handle = esp_coiiote;
    
    get_mac_adress();

    ESP_LOGI(tag_coiiote, "Esp-coiiote initialized successfully");
    ret =  ESP_OK;
    return ret;
err:
    ESP_LOGE(tag_coiiote, "Error to Conifgure");
    if (esp_coiiote)
    {
        free(esp_coiiote);
        esp_coiiote = NULL;
    }
    return ret;
}

void esp_coiiote_debug(){
    ESP_LOGI(tag_coiiote, "Esp-coiiote debug");
    ESP_LOGI(tag_coiiote, "Esp-coiiote NVS handle: %p", esp_coiite_handle->nvs_coiiote_handle);
    ESP_LOGI(tag_coiiote, "Esp-coiiote thingid: %s", esp_coiite_handle->thingid);
    ESP_LOGI(tag_coiiote, "Esp-coiiote thingpassword: %s", esp_coiite_handle->thingpassword);
    ESP_LOGI(tag_coiiote, "Esp-coiiote thingname: %s", esp_coiite_handle->thingname);
    ESP_LOGI(tag_coiiote, "Esp-coiiote workspace: %s", esp_coiite_handle->workspace);
    ESP_LOGI(tag_coiiote, "Esp-coiiote mac_str: %s", esp_coiite_handle->mac_str);
    ESP_LOGI(tag_coiiote, "Esp-coiiote server: %s", esp_coiite_handle->server);
    ESP_LOGI(tag_coiiote, "Esp-coiiote port: %lu", esp_coiite_handle->port);
}

/*
void http_rest_with_hostname_path(void)
{
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = (const char *)esp_coiite_handle->server, //CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .port = esp_coiite_handle->port,
        .path = "/device",
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .user_data = local_response_buffer,
        .event_handler = _http_event_handler,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(tag_coiiote, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(tag_coiiote, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    ESP_LOG_BUFFER_HEX(tag_coiiote, local_response_buffer, strlen(local_response_buffer));
    ESP_LOGI(tag_coiiote, "HTTP Response (JSON):\n%s", local_response_buffer);

    // POST
    const char *post_data = "field1=value1&field2=value2";
    esp_http_client_set_url(client, "/device");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(tag_coiiote, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(tag_coiiote, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    ESP_LOG_BUFFER_HEX(tag_coiiote, local_response_buffer, strlen(local_response_buffer));
    ESP_LOGI(tag_coiiote, "HTTP Response (JSON):\n%s", local_response_buffer);

    //DELETE
    esp_http_client_set_url(client, "/device/elemento");
    esp_http_client_set_method(client, HTTP_METHOD_DELETE);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(tag_coiiote, "HTTP DELETE Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(tag_coiiote, "HTTP DELETE request failed: %s", esp_err_to_name(err));
    }

    ESP_LOG_BUFFER_HEX(tag_coiiote, local_response_buffer, strlen(local_response_buffer));
    ESP_LOGI(tag_coiiote, "HTTP Response (JSON):\n%s", local_response_buffer);

    esp_http_client_cleanup(client);
}
*/
 
void esp_coiiote_access(){
    // POST
    char post_data[400];

     snprintf(post_data, sizeof(post_data), 
        "{"
          "\"thingid\":\"%s\","
          "\"thingname\":\"%s\","
          "\"thingpassword\":\"%s\","
          "\"workspace\":\"%s\","
          "\"macadress\":\"%s\""
        "}",
        esp_coiite_handle->thingid,
        esp_coiite_handle->thingname,
        esp_coiite_handle->thingpassword,
        esp_coiite_handle->workspace,
        esp_coiite_handle->mac_str
    );
    ESP_LOGI(tag_coiiote, "POST data: %s", post_data);

    char post_path[100];
    snprintf(post_path, sizeof(post_path), "/device/%s", esp_coiite_handle->thingname);
    ESP_LOGI(tag_coiiote, "POST path: %s", post_path);
    
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = (const char *)esp_coiite_handle->server, //CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .port = esp_coiite_handle->port,
        
        //.host = "192.168.1.12", //CONFIG_EXAMPLE_HTTP_ENDPOINT,
        //.port = 3000,
        .path = post_path,
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .user_data = local_response_buffer,
        .event_handler = _http_event_handler,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    
    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(tag_coiiote, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(tag_coiiote, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    ESP_LOG_BUFFER_HEX(tag_coiiote, local_response_buffer, strlen(local_response_buffer));
    ESP_LOGI(tag_coiiote, "HTTP Response (JSON):\n%s", local_response_buffer);

    esp_http_client_cleanup(client);

}

// FUNÇÃO QUE RETORNA O MAC_STRING
char* esp_coiiote_get_mac_str(void)
{
    if (esp_coiite_handle == NULL) {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiite_handle->mac_str;
}

// FUNÇÃO QUE RETORNA O PASSWORD DO THING
uint8_t* esp_coiiote_get_thing_password(void)
{
    if (esp_coiite_handle == NULL) {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiite_handle->thingpassword;
}

// função que retorna o workspace 
uint8_t* esp_coiiote_get_workspace(void)
{
    if (esp_coiite_handle == NULL) {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiite_handle->workspace;
}

// função que retorna thingname
uint8_t* esp_coiiote_get_thingname(void)
{
    if (esp_coiite_handle == NULL) {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiite_handle->thingname;
}
