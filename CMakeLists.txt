idf_component_register(SRCS "esp_coiiote.c"
                    INCLUDE_DIRS "include"
                    EMBED_TXTFILES "coiiote_cert.pem"
                    PRIV_REQUIRES
                        #nvs_flash
                        #esp_event
                        esp_netif
                        esp-tls
                        esp_http_client
                        esp_driver_gpio
                        app_update
                        protocol_examples_common
                        esp_http_server
                        esp_wifi
                        esp_https_ota)
