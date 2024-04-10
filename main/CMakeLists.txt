idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "certs/server.pem"
                                   "certs/server.key"
                    # PRIV_REQUIRES esp_http_server
                    EMBED_FILES  "./button.html.gz" 
                                   )
