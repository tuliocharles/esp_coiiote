#include <stdio.h>
#include "esp_coiiote.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_nvs.h"
#include "driver/gpio.h"
#include <string.h>
#include "esp_http_client.h"
#include <sys/param.h>
#include "esp_tls.h"

#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"

#include "esp_crt_bundle.h"

#include "protocol_examples_utils.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN (64)

// extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
// extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

extern const char coiiote_cert_pem_start[] asm("_binary_coiiote_cert_pem_start");
extern const char coiiote_cert_pem_end[] asm("_binary_coiiote_cert_pem_end");

// #define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

typedef struct esp_coiiote_t esp_coiiote_t;

typedef enum
{
    chart = 0,
    gauge,
    text,
    button
} WidgetType;

struct esp_coiiote_t
{
    esp_nvs_handle_t nvs_coiiote_handle; // NVS handle for CoIIoTe
    httpd_handle_t web_server;           // Handle of the web server
    uint8_t server[64];                  // Coiiote server address
    uint32_t port;                       // Coiiote server port
    char mac_str[13];                    // MAC address
    uint8_t thingid[256];                // Coiiote client ID
    uint8_t thingpassword[64];           // Coiiote username
    uint8_t thingname[64];               // Coiiote password
    uint8_t workspace[64];               // Coiiote workspace
    uint8_t jsonconfig[1024];            // JSON configuration for CoIIoTe
    char local_ip[16];                // Local IP address
    gpio_num_t status_io;
    gpio_num_t reset_io;
};

static esp_coiiote_handle_t esp_coiiote_handle = NULL;
static const char *tag_coiiote = "coiiote";

static esp_err_t _http_event_handler_ota(esp_http_client_event_t *evt)
{
    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGD("http", "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD("http", "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD("http", "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD("http", "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD("http", "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD("http", "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD("http", "HTTP_EVENT_DISCONNECTED");
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGD("http", "HTTP_EVENT_REDIRECT");
        break;
    }
    return ESP_OK;
}

static esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer; // Buffer to store response of http request from event handler
    static int output_len;      // Stores number of bytes read
    switch (evt->event_id)
    {
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
        if (output_len == 0 && evt->user_data)
        {
            // we are just starting to copy the output data into the use
            memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
        }
        /*
         *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
         *  However, event handler can also be used in case chunked encoding is used.
         */
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            // If user_data buffer is configured, copy the response into the buffer
            int copy_len = 0;
            if (evt->user_data)
            {
                // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                if (copy_len)
                {
                    memcpy(evt->user_data + output_len, evt->data, copy_len);
                }
            }
            else
            {
                int content_len = esp_http_client_get_content_length(evt->client);
                if (output_buffer == NULL)
                {
                    // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                    output_buffer = (char *)calloc(content_len + 1, sizeof(char));
                    output_len = 0;
                    if (output_buffer == NULL)
                    {
                        ESP_LOGE(tag_coiiote, "Failed to allocate memory for output buffer");
                        return ESP_FAIL;
                    }
                }
                copy_len = MIN(evt->data_len, (content_len - output_len));
                if (copy_len)
                {
                    memcpy(output_buffer + output_len, evt->data, copy_len);
                }
            }
            output_len += copy_len;
        }

        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(tag_coiiote, "HTTP_EVENT_ON_FINISH");
        if (output_buffer != NULL)
        {
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
        if (err != 0)
        {
            ESP_LOGI(tag_coiiote, "Last esp error code: 0x%x", err);
            ESP_LOGI(tag_coiiote, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        if (output_buffer != NULL)
        {
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

static char *mac_bytes_to_hexstr(const uint8_t mac[6], char out_str[13])
{
    for (int i = 0; i < 6; ++i)
    {
        // Escreve dois dígitos hex em uppercase sem separador
        sprintf(out_str + i * 2, "%02X", mac[i]);
    }
    out_str[12] = '\0'; // null-terminator
    return out_str;
}

static void get_mac_adress(void)
{
    uint8_t mac[6]; // MAC address
    esp_err_t ret;

    ret = esp_read_mac(mac, ESP_MAC_EFUSE_FACTORY);
    if (ret != ESP_OK)
    {
        ESP_LOGW(tag_coiiote, "Erro ao ler MAC de fábrica: %s\n", esp_err_to_name(ret));
        return;
    }

    // Exibe em formato hexadecimal
    ESP_LOGI(tag_coiiote, "MAC de fábrica (EFUSE_FACTORY): %02X:%02X:%02X:%02X:%02X:%02X\n",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Converte para string hexadecimal
    char mac_str[13]; // 6 bytes * 2 hex digits + 1 null terminator
    mac_bytes_to_hexstr(mac, esp_coiiote_handle->mac_str);
    ESP_LOGI(tag_coiiote, "MAC de fábrica (EFUSE_FACTORY) em string: %s\n", mac_str);
}

static esp_err_t read_nvs_string_to_buffer(const char *key, esp_nvs_handle_t aux_nvs_coiiote_p, uint8_t *dest)
{

    char *generic_p = NULL;
    esp_nvs_change_key(key, aux_nvs_coiiote_p);
    if (esp_nvs_read_string(aux_nvs_coiiote_p, &generic_p) != ESP_OK)
    {
        ESP_LOGE(tag_coiiote, "Error to read Password");
        dest[0] = '\0'; // Initialize to empty string if read fails
    }
    if (generic_p != NULL)
    {
        memcpy(dest, generic_p, strlen(generic_p) + 1);
    }
    else
    {
        ESP_LOGW(tag_coiiote, "generic_p é NULL, ignorando memcpy.");
        return ESP_ERR_NOT_FOUND; // Return error if no data found
    }

    return ESP_OK;
}

esp_err_t esp_coiiote_init(esp_coiiote_config_t *config)
{
    esp_err_t ret = ESP_OK;
    esp_coiiote_t *esp_coiiote = NULL;
    ESP_GOTO_ON_FALSE(config, ESP_ERR_INVALID_ARG, err, tag_coiiote, "Invalid arguments");
    esp_coiiote = calloc(1, sizeof(esp_coiiote_t));

    if (esp_coiiote == NULL)
    {
        ESP_LOGE(tag_coiiote, "Erro ao alocar memória para esp_coiiote_handle\n");
        return ESP_ERR_NO_MEM;
    }

    // copia os parâmetros de configuração
    memcpy(esp_coiiote->server, config->server, sizeof(esp_coiiote->server));
    esp_coiiote->port = config->port;

    // esp_coiiote->nvs_coiiote_handle = config->nvs_coiiote_handle;
    // ESP_GOTO_ON_ERROR(esp_coiiote->nvs_coiiote_handle, err, tag_coiiote, "Error to get NVS handle");

    esp_nvs_config_t esp_nvs_coiiote_config = {
        .name_space = "coiiote_nvs",
        .key = "thingid",
        .value_size = 1024,
    };

    if (init_esp_nvs(&esp_nvs_coiiote_config, &esp_coiiote->nvs_coiiote_handle) == ESP_OK)
    {
        ESP_LOGI(tag_coiiote, "NVS for CoIIote Created Successfully");
    }
    else
    {
        ESP_LOGE(tag_coiiote, "NVS for CoIIote not created");
    };

    read_nvs_string_to_buffer("thingid", esp_coiiote->nvs_coiiote_handle, esp_coiiote->thingid);
    read_nvs_string_to_buffer("thingpassword", esp_coiiote->nvs_coiiote_handle, esp_coiiote->thingpassword);
    read_nvs_string_to_buffer("thingname", esp_coiiote->nvs_coiiote_handle, esp_coiiote->thingname);
    read_nvs_string_to_buffer("workspace", esp_coiiote->nvs_coiiote_handle, esp_coiiote->workspace);
    read_nvs_string_to_buffer("jsonconfig", esp_coiiote->nvs_coiiote_handle, esp_coiiote->jsonconfig); // Read JSON config from NVS

    esp_coiiote_handle = esp_coiiote;

    get_mac_adress();

    ESP_LOGI(tag_coiiote, "Esp-coiiote initialized successfully");
    ret = ESP_OK;
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

void esp_coiiote_debug()
{
    ESP_LOGI(tag_coiiote, "Esp-coiiote debug");
    ESP_LOGI(tag_coiiote, "Esp-coiiote NVS handle: %p", esp_coiiote_handle->nvs_coiiote_handle);
    ESP_LOGI(tag_coiiote, "Esp-coiiote thingid: %s", esp_coiiote_handle->thingid);
    ESP_LOGI(tag_coiiote, "Esp-coiiote thingpassword: %s", esp_coiiote_handle->thingpassword);
    ESP_LOGI(tag_coiiote, "Esp-coiiote thingname: %s", esp_coiiote_handle->thingname);
    ESP_LOGI(tag_coiiote, "Esp-coiiote workspace: %s", esp_coiiote_handle->workspace);
    ESP_LOGI(tag_coiiote, "Esp-coiiote mac_str: %s", esp_coiiote_handle->mac_str);
    ESP_LOGI(tag_coiiote, "Esp-coiiote server: %s", esp_coiiote_handle->server);
    ESP_LOGI(tag_coiiote, "Esp-coiiote port: %lu", esp_coiiote_handle->port);
    ESP_LOGI(tag_coiiote, "Esp-coiiote json_config: %s", esp_coiiote_handle->jsonconfig);
}

void esp_coiiote_access()
{
    // POST
    char post_data[800];

    snprintf(post_data, sizeof(post_data),
             "{"
             "\"thingid\":\"%s\","
             "\"thingname\":\"%s\","
             "\"thingpassword\":\"%s\","
             "\"workspace\":\"%s\","
             "\"macadress\":\"%s\""
             "}",
             esp_coiiote_handle->thingid,
             esp_coiiote_handle->thingname,
             esp_coiiote_handle->thingpassword,
             esp_coiiote_handle->workspace,
             esp_coiiote_handle->mac_str);
    ESP_LOGI(tag_coiiote, "POST data: %s", post_data);

    char post_path[100];
    snprintf(post_path, sizeof(post_path), "/device/%s", esp_coiiote_handle->thingname);
    ESP_LOGI(tag_coiiote, "POST path: %s", post_path);

    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = (const char *)esp_coiiote_handle->server, // CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .port = esp_coiiote_handle->port,

        //.host = "192.168.1.12", //CONFIG_EXAMPLE_HTTP_ENDPOINT,
        //.port = 3000,
        .path = post_path,
        .transport_type = HTTP_TRANSPORT_OVER_SSL, // HTTP_TRANSPORT_OVER_TCP,
        .user_data = local_response_buffer,
        .event_handler = _http_event_handler,
        .cert_pem = coiiote_cert_pem_start,

    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(tag_coiiote, "HTTP POST Status = %d, content_length = %" PRId64,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(tag_coiiote, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    ESP_LOG_BUFFER_HEX(tag_coiiote, local_response_buffer, strlen(local_response_buffer));
    ESP_LOGI(tag_coiiote, "HTTP Response (JSON):\n%s", local_response_buffer);

    esp_http_client_cleanup(client);
}

char *esp_coiiote_get_mac_str(void)
{
    if (esp_coiiote_handle == NULL)
    {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiiote_handle->mac_str;
}

uint8_t *esp_coiiote_get_thing_password(void)
{
    if (esp_coiiote_handle == NULL)
    {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiiote_handle->thingpassword;
}

uint8_t *esp_coiiote_get_workspace(void)
{
    if (esp_coiiote_handle == NULL)
    {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiiote_handle->workspace;
}

uint8_t *esp_coiiote_get_thingname(void)
{
    if (esp_coiiote_handle == NULL)
    {
        ESP_LOGE(tag_coiiote, "Esp-coiiote handle is NULL");
        return NULL;
    }
    return esp_coiiote_handle->thingname;
}

void esp_coiiote_ota(const char *url)
{
    ESP_LOGI(tag_coiiote, "Starting OTA update from URL: %s", url);

    // começa aqui a parte de OTA
    esp_http_client_config_t config = {
        .url = url,
        .cert_pem = (char *)coiiote_cert_pem_start,
        .event_handler = _http_event_handler_ota,
        .keep_alive_enable = true,
    };

    config.skip_cert_common_name_check = true;

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };
    ESP_LOGI(tag_coiiote, "Attempting to download update from %s", config.url);

    esp_err_t ret = esp_https_ota(&ota_config);
    if (ret == ESP_OK)
    {
        ESP_LOGI(tag_coiiote, "OTA Succeed, Rebooting...");
        esp_restart();
    }
    else
    {
        ESP_LOGE(tag_coiiote, "Firmware upgrade failed");
    }
}

// webserver
//  convert a hex digit to its integer value
static char from_hex(char ch)
{
    if (isdigit((unsigned char)ch))
        return ch - '0';
    if (isupper((unsigned char)ch))
        return ch - 'A' + 10;
    return ch - 'a' + 10;
}

// decod percent‑encoding (URL) acording to RFC 3986
// https://datatracker.ietf.org/doc/html/rfc3986#section-2.1
static void url_decode(char *dst, const char *src)
{
    while (*src)
    {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2]))
        {
            *dst++ = from_hex(src[1]) << 4 | from_hex(src[2]);
            src += 3;
        }
        else if (*src == '+')
        {
            *dst++ = ' ';
            src++;
        }
        else
        {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// Save configuration JSON to NVS
void esp_coiiote_write_config(const char *value)
{
    esp_nvs_change_key("jsonconfig", esp_coiiote_handle->nvs_coiiote_handle);
    char configjson[1000];
    url_decode(configjson, value);
    esp_nvs_write_string(configjson, esp_coiiote_handle->nvs_coiiote_handle);
}

/* An HTTP GET handler */
static esp_err_t getssid_get_handler(httpd_req_t *req)
{
    char *buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found URL query => %s", buf);
            char param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN], dec_param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN] = {0};
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(tag_coiiote, "Found URL query parameter => query1=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(tag_coiiote, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(tag_coiiote, "Found URL query parameter => query3=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(tag_coiiote, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(tag_coiiote, "Found URL query parameter => query2=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(tag_coiiote, "Decoded query parameter => %s", dec_param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    char thingid[64];
    char *p = NULL;
    esp_nvs_change_key("thingid", esp_coiiote_handle->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote_handle->nvs_coiiote_handle, &p) != ESP_OK)
    {
        thingid[0] = '\0';
        ESP_LOGW(tag_coiiote, "Error to read Thing-ID");
    }
    else
    {
        strcpy(thingid, p);
    }

    char thingname[64];
    esp_nvs_change_key("thingname", esp_coiiote_handle->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote_handle->nvs_coiiote_handle, &p) != ESP_OK)
    {
        thingname[0] = '\0';
        ESP_LOGW(tag_coiiote, "Error to read Thing-NAME");
    }
    else
    {
        strcpy(thingname, p);
    }

    char workspace[64];
    esp_nvs_change_key("workspace", esp_coiiote_handle->nvs_coiiote_handle);
    if (esp_nvs_read_string(esp_coiiote_handle->nvs_coiiote_handle, &p) != ESP_OK)
    {
        workspace[0] = '\0';
        ESP_LOGW(tag_coiiote, "Error to read WORKSPACE");
    }
    else
    {
        strcpy(workspace, p);
    }

    static char wifi_form_html[2048];

    sprintf(wifi_form_html,
            "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<style>"
            "body {  margin: 0;  padding: 0;  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;  background: linear-gradient(135deg, #e0eafc, #cfdef3);  display: flex;  flex-direction: column;  align-items: center;}"
            ".container {  text-align: center;  background: white;  padding: 40px 60px;  border-radius: 16px;  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);}"
            ".form-group {  margin: 10px 0;  width: 100%%;  max-width: 400px;  text-align: left; }"
            "input {  width: 100%%;  padding: 10px;  font-size: 1rem;  margin-top: 5px;  border: 1px solid #ccc;  border-radius: 4px;}"
            "button {  width: 100%%;  padding: 12px;  background-color: #007bff;  color: white;  border: none;  border-radius: 4px;  font-size: 1rem;  cursor: pointer;  margin-top: 10px; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class=\"container\">"
            "<h2>CoIIoTe</h2>"
            "<form action=\"/save\" method=\"post\">"
            "Thing-ID: <input name=\"thingid\" type=\"text\" value=\"%s\"><br>"
            "Thing-Name: <input name=\"thingname\" type=\"text\" value=\"%s\"><br>"
            "Thing-Password: <input name=\"thingpassword\" type=\"password\"> <br>"
            "Workspace: <input name=\"workspace\" type=\"text\" value=\"%s\"><br><br>"
            "<button type=\"submit\">Enviar</button>"
            "</form>"
            "</div>"
            "</body></html>",
            thingid, thingname, workspace);

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char *resp_str = (const char *)wifi_form_html;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0)
    {
        ESP_LOGI(tag_coiiote, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t getssid = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = getssid_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t config_json_get_handler(httpd_req_t *req)
{
    char *buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, tag_coiiote, "buffer alloc failed");
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(tag_coiiote, "Found URL query => %s", buf);
            char param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN], dec_param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN] = {0};
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(tag_coiiote, "Found URL query parameter => query1=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(tag_coiiote, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(tag_coiiote, "Found URL query parameter => query3=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(tag_coiiote, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(tag_coiiote, "Found URL query parameter => query2=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(tag_coiiote, "Decoded query parameter => %s", dec_param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    static char wifi_form_html[8192];

    snprintf(wifi_form_html, sizeof(wifi_form_html),
             "<!DOCTYPE html>"
             "<html lang=\"pt-BR\">"
             "<head>"
             "  <meta charset=\"utf-8\" />"
             "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />"
             "  <title>CoIIoTe - Configurar Gráficos</title>"
             "  <style>"
             "    body { margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg,#e0eafc,#cfdef3); display:flex; justify-content:center; align-items:flex-start; min-height:100vh; }"
             "    .container { margin: 32px; text-align:left; background:white; padding:24px; border-radius:12px; box-shadow:0 6px 24px rgba(0,0,0,0.12); width:100%%; max-width:920px; }"
             "    h2{ margin:0 0 12px 0; font-size:1.25rem; }"
             "    form .row { display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap; }"
             "    .field-group { background:#f7f9ff; padding:12px; border-radius:10px; margin-bottom:12px; position:relative; border:1px solid rgba(0,0,0,0.04); }"
             "    .field-group .remove { position:absolute; right:10px; top:10px; background:transparent; border:none; cursor:pointer; font-size:0.9rem; color:#b00; }"
             "    label { display:block; font-size:0.85rem; margin-bottom:4px; }"
             "    input, select { width:100%%; padding:8px 10px; border-radius:6px; border:1px solid #ccc; font-size:0.95rem; }"
             "    .grid { display:grid; grid-template-columns: repeat(2, 1fr); gap:12px; }"
             "    .controls { display:flex; gap:12px; margin-top:8px; }"
             "    button.primary { background:#007bff; color:white; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; }"
             "    button.ghost { background:transparent; border:1px solid #007bff; color:#007bff; padding:10px 14px; border-radius:8px; cursor:pointer; }"
             "    .add-btn { display:inline-flex; align-items:center; gap:8px; }"
             "    small.helper { display:block; margin-top:6px; color:#666; }"
             "    @media (max-width:600px){ .grid{ grid-template-columns:1fr; } }"
             "  </style>"
             "</head>"
             "<body>"
             "  <div class=\"container\">"
             "    <h2>CoIIoTe \u2014 Configurar Dados para o Gr\u00E1fico</h2>"
             "    <form id=\"configForm\" action=\"/saveconfig\" method=\"post\">"
             "      <div id=\"fieldsContainer\">"
             "        <!-- Um grupo inicial ser\u00E1 inserido pelo script ao carregar a p\u00E1gina -->"
             "      </div>"
             ""
             "      <div class=\"controls\">"
             "        <button type=\"button\" id=\"addBtn\" class=\"primary add-btn\">+ Adicionar dado</button>"
             "        <button type=\"submit\" class=\"ghost\">Enviar</button>"
             "      </div>"
             ""
             "      <p style=\"margin-top:10px\"><small class=\"helper\">Voc\u00EA pode adicionar v\u00E1rios conjuntos de campos. Cada grupo cont\u00E9m: tipo (chart), nome da vari\u00E1vel medida, nome e escala dos eixos X e Y.</small></p>"
             "    </form>"
             ""
             "    <template id=\"fieldTemplate\">"
             "      <div class=\"field-group\">"
             "        <button type=\"button\" class=\"remove\" title=\"Remover\" onclick=\"removeField(this)\">x</button>"
             "        <div class=\"grid\">"
             "          <div>"
             "            <label>Tipo de dado</label>"
             "            <select name=\"type\">"
             "              <option value=\"chart\" selected>chart</option>"
             "            </select>"
             "          </div>"
             ""
             "          <div>"
             "            <label>Nome da vari\u00E1vel medida</label>"
             "            <input name=\"varName\" type=\"text\" placeholder=\"ex: temperatura\" required />"
             "          </div>"
             ""
             "          <div>"
             "            <label>Nome eixo X</label>"
             "            <input name=\"xName\" type=\"text\" placeholder=\"ex: tempo\" required />"
             "          </div>"
             ""
             "          <div>"
             "            <label>Escala eixo X</label>"
             "            <input name=\"xScale\" type=\"text\" placeholder=\"ex: segundos, 0-60\" />"
             "          </div>"
             ""
             "          <div>"
             "            <label>Nome eixo Y</label>"
             "            <input name=\"yName\" type=\"text\" placeholder=\"ex: n\u00EDvel (cm)\" required />"
             "          </div>"
             ""
             "          <div>"
             "            <label>Escala eixo Y</label>"
             "            <input name=\"yScale\" type=\"text\" placeholder=\"ex: 0-100\" />"
             "          </div>"
             "        </div>"
             "      </div>"
             "    </template>"
             ""
             "  </div>"
             ""
             "  <script>"
             "    const container = document.getElementById(\"fieldsContainer\");"
             "    const template = document.getElementById(\"fieldTemplate\");"
             "    const addBtn = document.getElementById(\"addBtn\");"
             ""
             "    function addField(prefill = {}) {"
             "      const node = template.content.cloneNode(true);"
             "      if (prefill.varName) node.querySelector(\"input[name='varName']\").value = prefill.varName;"
             "      if (prefill.xName)  node.querySelector(\"input[name='xName']\").value  = prefill.xName;"
             "      if (prefill.xScale) node.querySelector(\"input[name='xScale']\").value = prefill.xScale;"
             "      if (prefill.yName)  node.querySelector(\"input[name='yName[]']\").value  = prefill.yName;"
             "      if (prefill.yScale) node.querySelector(\"input[name='yScale[]']\").value = prefill.yScale;"
             "      container.appendChild(node);"
             "      const allVarInputs = container.querySelectorAll(\"input[name='varName[]']\");"
             "      if (allVarInputs.length) allVarInputs[allVarInputs.length - 1].focus();"
             "    }"
             ""
             "    function removeField(btn) {"
             "      const group = btn.closest('.field-group');"
             "      if (!group) return;"
             "      group.remove();"
             "    }"
             ""
             "    document.addEventListener('DOMContentLoaded', () => {"
             "      addField();"
             "    });"
             ""
             "    addBtn.addEventListener('click', () => addField());"
             ""
             "    document.getElementById('configForm').addEventListener('submit', (ev) => {"
             "      const groups = container.querySelectorAll('.field-group');"
             "      if (groups.length === 0) {"
             "        ev.preventDefault();"
             "        alert('Adicione ao menos um conjunto de dados antes de enviar.');"
             "      }"
             "    });"
             "  </script>"
             "</body>"
             "</html>");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char *resp_str = (const char *)wifi_form_html;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0)
    {
        ESP_LOGI(tag_coiiote, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t config_json = {
    .uri = "/config",
    .method = HTTP_GET,
    .handler = config_json_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

/* An HTTP POST handler */
static esp_err_t savessid_post_handler(httpd_req_t *req)
{
    char buf[1000];
    int ret, remaining = req->content_len;

    // void *ctx = httpd_get_global_user_ctx(req->handle);
    // esp_coiiote_handle_t handle = (esp_coiiote_handle_t)ctx;

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                                  MIN(remaining, sizeof(buf)))) <= 0)
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(tag_coiiote, "=========== RECEIVED DATA ==========");
        ESP_LOGI(tag_coiiote, "%.*s", ret, buf);
        ESP_LOGI(tag_coiiote, "====================================");

        char *saveptr1, *saveptr2;
        char *str = strndup(buf, ret);
        char *pair = strtok_r(str, "&", &saveptr1);
        while (pair)
        {
            char *key = strtok_r(pair, "=", &saveptr2);
            char *value = strtok_r(NULL, "=", &saveptr2);
            printf("Chave: %s, Valor: %s\n", key, value);
            pair = strtok_r(NULL, "&", &saveptr1);
            // test
            if (strcmp(key, "thingid") == 0)
            {
                esp_nvs_change_key("thingid", esp_coiiote_handle->nvs_coiiote_handle);
                char thingid[256];
                url_decode(thingid, value);
                esp_nvs_write_string(thingid, esp_coiiote_handle->nvs_coiiote_handle);
            }
            else if (strcmp(key, "thingname") == 0)
            {
                esp_nvs_change_key("thingname", esp_coiiote_handle->nvs_coiiote_handle);
                char thingname[100];
                url_decode(thingname, value);
                esp_nvs_write_string(thingname, esp_coiiote_handle->nvs_coiiote_handle);
            }
            else if (strcmp(key, "thingpassword") == 0)
            {
                esp_nvs_change_key("thingpassword", esp_coiiote_handle->nvs_coiiote_handle);
                char thingpassword[100];
                url_decode(thingpassword, value);
                esp_nvs_write_string(thingpassword, esp_coiiote_handle->nvs_coiiote_handle);
            }
            else if (strcmp(key, "workspace") == 0)
            {
                esp_nvs_change_key("workspace", esp_coiiote_handle->nvs_coiiote_handle);
                char workspace[100];
                url_decode(workspace, value);
                esp_nvs_write_string(workspace, esp_coiiote_handle->nvs_coiiote_handle);
            }
            else
            {
                ESP_LOGI(tag_coiiote, "Chave não reconhecida: %s", key);
            }
        }
        free(str);

        // salva na memória
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t savessid = {
    .uri = "/save",
    .method = HTTP_POST,
    .handler = savessid_post_handler,
    .user_ctx = NULL};

static esp_err_t config_json_post_handler(httpd_req_t *req)
{
    char buf[1000];
    int ret, remaining = req->content_len;

    // void *ctx = httpd_get_global_user_ctx(req->handle);
    // esp_coiiote_handle_t handle = (esp_coiiote_handle_t)ctx;

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                                  MIN(remaining, sizeof(buf)))) <= 0)
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(tag_coiiote, "=========== RECEIVED DATA ==========");
        ESP_LOGI(tag_coiiote, "%.*s", ret, buf);
        ESP_LOGI(tag_coiiote, "====================================");

        // preparando para salvar os dados
        char config_data[4][100][30];
        int config_type_count = 0;
        int confing_instance_count[4] = {0};
        // cada linha é um tipo (type)
        // cada coluna é uma instância (1, 2, 3, ...)

        char *saveptr1, *saveptr2;
        char *str = strndup(buf, ret);
        char *pair = strtok_r(str, "&", &saveptr1);

        while (pair)
        {
            char *key = strtok_r(pair, "=", &saveptr2);
            char *value = strtok_r(NULL, "=", &saveptr2);
            printf("Chave: %s, Valor: %s\n", key, value);
            pair = strtok_r(NULL, "&", &saveptr1);
            // test
            if (strcmp(key, "type") == 0)
            {
                if (strcmp(value, "chart") == 0)
                {
                    printf("Tipo: %s\n", value);
                    config_type_count = 0;
                }
            }
            else
            {
                snprintf(config_data[config_type_count][confing_instance_count[config_type_count]],
                         sizeof config_data[config_type_count][confing_instance_count[config_type_count]], "\"%s\":\"%s\"", key, value);
                confing_instance_count[config_type_count]++;
            }
        }
        free(str);

        for (int j = 0; j < confing_instance_count[0]; j++)
        {
            printf("  Instância %d: %s\n", j, config_data[0][j]);
        }

        // monta o JSON -- por enquanto só funciona para 1 chart. tem que montar para vários charts e vários widgets

        size_t used = 0;
        char out[1024];

        used += snprintf(out + used, sizeof(out) - used, "{\"charts\":[{");

        for (int i = 0; i < confing_instance_count[0]; i++)
        {
            int field = i % 5;
            bool last = (i == confing_instance_count[0] - 1);
            // adiciona vírgula antes de cada item, exceto o primeiro
            if ((field != 0))
            {
                used += snprintf(out + used, sizeof(out) - used, ",");
            }
            used += snprintf(out + used, sizeof(out) - used, "%s", config_data[0][i]);

            if (field == 4 && !last)
            {
                used += snprintf(out + used, sizeof(out) - used, "},{");
            }
        }

        used += snprintf(out + used, sizeof(out) - used, "}]}");

        printf("JSON final: %s\n", out);

        // falta salvar na memória do esp.
        esp_coiiote_write_config(out);

        // monta o json
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t save_config_json = {
    .uri = "/saveconfig",
    .method = HTTP_POST,
    .handler = config_json_post_handler,
    .user_ctx = NULL};

static esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/getssid", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/getssid URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    }
    else if (strcmp("/savessid", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/savessid URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static httpd_handle_t start_webserver()
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(tag_coiiote, "Starting server on port: '%d'", config.server_port);

    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(tag_coiiote, "Registering URI handlers");
        httpd_register_uri_handler(server, &getssid);
        httpd_register_uri_handler(server, &savessid);
        httpd_register_uri_handler(server, &config_json);
        httpd_register_uri_handler(server, &save_config_json);
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http_404_error_handler);
        return server;
    }

    ESP_LOGI(tag_coiiote, "Error starting server!");
    return NULL;
}

static void disconnect_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server)
    {
        ESP_LOGI(tag_coiiote, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK)
        {
            *server = NULL;
        }
        else
        {
            ESP_LOGE(tag_coiiote, "Failed to stop http server");
        }
    }
}

static void connect_handler(void *arg, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
    esp_coiiote_handle_t handle = (esp_coiiote_handle_t)arg;
    // httpd_handle_t *server = (httpd_handle_t *)arg;
    printf("handle no connect: %p\n", handle);
    if (handle->web_server == NULL)
    {
        ESP_LOGI(tag_coiiote, "Starting webserver");
        handle->web_server = start_webserver();
    }
}

void esp_coiiote_webserver_init()
{

    esp_coiiote_handle->web_server = NULL;

    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, esp_coiiote_handle));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &esp_coiiote_handle->web_server));

    esp_coiiote_handle->web_server = start_webserver();

    if (esp_coiiote_handle->web_server == NULL)
    {
        ESP_LOGE(tag_coiiote, "Failed to start webserver");
    }
    else
    {
        ESP_LOGI(tag_coiiote, "Webserver started successfully");
    }
}

void esp_coiiote_config()
{

    // POST
    char post_data[2048];

    snprintf(post_data, sizeof(post_data),
             "{"
             "\"thingname\":\"%s\","
             "\"thingpassword\":\"%s\","
             "\"workspace\":\"%s\","
             "\"macadress\":\"%s\","
             "\"local_ip\":\"%s\","
             "%s",
             esp_coiiote_handle->thingname,
             esp_coiiote_handle->thingpassword,
             esp_coiiote_handle->workspace,
             esp_coiiote_handle->mac_str,
             esp_coiiote_handle->local_ip,
             esp_coiiote_handle->jsonconfig+1); // +1 para pular o '{' inicial

    
    ESP_LOGI(tag_coiiote, "POST data: %s", post_data);

    char post_path[100];
    snprintf(post_path, sizeof(post_path), "/device/%s/config", esp_coiiote_handle->thingname);
    ESP_LOGI(tag_coiiote, "POST path: %s", post_path);

    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = (const char *)esp_coiiote_handle->server, // CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .port = esp_coiiote_handle->port,

        //.host = "192.168.1.12", //CONFIG_EXAMPLE_HTTP_ENDPOINT,
        //.port = 3000,
        .path = post_path,
        .transport_type = HTTP_TRANSPORT_OVER_SSL, // HTTP_TRANSPORT_OVER_TCP,
        .user_data = local_response_buffer,
        .event_handler = _http_event_handler,
        .cert_pem = coiiote_cert_pem_start,

    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(tag_coiiote, "HTTP POST Status = %d, content_length = %" PRId64,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(tag_coiiote, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    ESP_LOG_BUFFER_HEX(tag_coiiote, local_response_buffer, strlen(local_response_buffer));
    ESP_LOGI(tag_coiiote, "HTTP Response (JSON):\n%s", local_response_buffer);

    esp_http_client_cleanup(client);
}

void esp_local_ip(const char *ip)
{
    sprintf(esp_coiiote_handle->local_ip, "%s", ip);
}