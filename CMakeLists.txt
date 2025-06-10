idf_component_register(SRCS "esp_coiiote.c"
                    INCLUDE_DIRS "include"
                     PRIV_REQUIRES
                        #nvs_flash
                        #esp_event
                        #esp_netif
                        #protocol_examples_common
                        esp-tls
                        #esp_http_server
                        esp_http_client
                        esp_driver_gpio)
