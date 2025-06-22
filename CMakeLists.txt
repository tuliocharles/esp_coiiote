idf_component_register(SRCS "esp_coiiote.c"
                    INCLUDE_DIRS "include"
                    EMBED_TXTFILES "server_certs/ca_cert.pem"
                     PRIV_REQUIRES
                        #nvs_flash
                        #esp_event
                        #esp_netif
                        #protocol_examples_common
                        esp-tls
                        #esp_http_server
                        esp_http_client
                        esp_driver_gpio
                        app_update
                        esp_https_ota)
