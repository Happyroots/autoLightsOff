/* Simple HTTP + SSL Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"

#include <esp_https_server.h>
#include "esp_tls.h"
#include "sdkconfig.h"

#include "driver/mcpwm_prelude.h"
/* A simple example that demonstrates how to create GET and POST
 * handlers and start an HTTPS server.
*/

static const char *TAG = "example";
static mcpwm_cmpr_handle_t comparator = NULL;

// Please consult the datasheet of your servo before changing the following parameters
#define SERVO_MIN_PULSEWIDTH_US 500  // Minimum pulse width in microsecond
#define SERVO_MAX_PULSEWIDTH_US 2500  // Maximum pulse width in microsecond
#define SERVO_MIN_DEGREE        -90   // Minimum angle
#define SERVO_MAX_DEGREE        90    // Maximum angle

#define SERVO_PULSE_GPIO             13        // GPIO connects to the PWM signal line
#define SERVO_TIMEBASE_RESOLUTION_HZ 1000000  // 1MHz, 1us per tick
#define SERVO_TIMEBASE_PERIOD        20000    // 20000 ticks, 20ms

static inline uint32_t example_angle_to_compare(int angle)
{
    return (angle - SERVO_MIN_DEGREE) * (SERVO_MAX_PULSEWIDTH_US - SERVO_MIN_PULSEWIDTH_US) / (SERVO_MAX_DEGREE - SERVO_MIN_DEGREE) + SERVO_MIN_PULSEWIDTH_US;
}

/* An HTTP GET handler */
static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");

    // //路径问题
    extern const char html_start[] asm("_binary_button_html_gz_start");
    extern const char html_end[]   asm("_binary_button_html_gz_end");
    const size_t html_size = (html_end - html_start);
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req,  (const char*) html_start, html_size);

    // httpd_resp_send(req, "<h1>Hello Secure World!</h1>", HTTPD_RESP_USE_STRLEN);
    

    return ESP_OK;
}

#include "cJSON.h"
bool isLightOn = false;

esp_err_t set_light_state_handler(httpd_req_t *req) {
    char buf[100];
    memset(buf, 0, sizeof(buf));
    int ret, remaining = req->content_len;


    while (remaining > 0) {
        ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));
        // ESP_LOGI(TAG, "Received data: %s", buf);


        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            return ESP_FAIL;
        }
        remaining -= ret;




        // 解析收到的数据
        cJSON *root = cJSON_Parse(buf);
        if (root == NULL) {
            ESP_LOGE(TAG, "Failed to parse JSON");
            return ESP_FAIL;
        }
        cJSON *state = cJSON_GetObjectItem(root, "state");
        if (state != NULL) {
            if (state->type == cJSON_True) {
                isLightOn = true;
                // 在这里执行灯开启的操作
                ESP_LOGI(TAG, "true decoding");
                //需要弄清楚 限位
                ESP_ERROR_CHECK(mcpwm_comparator_set_compare_value(comparator, example_angle_to_compare(45)));

            } else if (state->type == cJSON_False) {
                isLightOn = false;
                // 在这里执行灯关闭的操作
                ESP_LOGI(TAG, "false decoding");
                ESP_ERROR_CHECK(mcpwm_comparator_set_compare_value(comparator, example_angle_to_compare(-45)));

            } 
        }
        cJSON_Delete(root);
    }

    httpd_resp_send(req, "Light state updated", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}


#if CONFIG_EXAMPLE_ENABLE_HTTPS_USER_CALLBACK
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
static void print_peer_cert_info(const mbedtls_ssl_context *ssl)
{
    const mbedtls_x509_crt *cert;
    const size_t buf_size = 1024;
    char *buf = calloc(buf_size, sizeof(char));
    if (buf == NULL) {
        ESP_LOGE(TAG, "Out of memory - Callback execution failed!");
        return;
    }

    // Logging the peer certificate info
    cert = mbedtls_ssl_get_peer_cert(ssl);
    if (cert != NULL) {
        mbedtls_x509_crt_info((char *) buf, buf_size - 1, "    ", cert);
        ESP_LOGI(TAG, "Peer certificate info:\n%s", buf);
    } else {
        ESP_LOGW(TAG, "Could not obtain the peer certificate!");
    }

    free(buf);
}
#endif
/**
 * Example callback function to get the certificate of connected clients,
 * whenever a new SSL connection is created and closed
 *
 * Can also be used to other information like Socket FD, Connection state, etc.
 *
 * NOTE: This callback will not be able to obtain the client certificate if the
 * following config `Set minimum Certificate Verification mode to Optional` is
 * not enabled (enabled by default in this example).
 *
 * The config option is found here - Component config → ESP-TLS
 *
 */
static void https_server_user_callback(esp_https_server_user_cb_arg_t *user_cb)
{
    ESP_LOGI(TAG, "User callback invoked!");
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
    mbedtls_ssl_context *ssl_ctx = NULL;
#endif
    switch(user_cb->user_cb_state) {
        case HTTPD_SSL_USER_CB_SESS_CREATE:
            ESP_LOGD(TAG, "At session creation");

            // Logging the socket FD
            int sockfd = -1;
            esp_err_t esp_ret;
            esp_ret = esp_tls_get_conn_sockfd(user_cb->tls, &sockfd);
            if (esp_ret != ESP_OK) {
                ESP_LOGE(TAG, "Error in obtaining the sockfd from tls context");
                break;
            }
            ESP_LOGI(TAG, "Socket FD: %d", sockfd);
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
            ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(user_cb->tls);
            if (ssl_ctx == NULL) {
                ESP_LOGE(TAG, "Error in obtaining ssl context");
                break;
            }
            // Logging the current ciphersuite
            ESP_LOGI(TAG, "Current Ciphersuite: %s", mbedtls_ssl_get_ciphersuite(ssl_ctx));
#endif
            break;

        case HTTPD_SSL_USER_CB_SESS_CLOSE:
            ESP_LOGD(TAG, "At session close");
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
            // Logging the peer certificate
            ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(user_cb->tls);
            if (ssl_ctx == NULL) {
                ESP_LOGE(TAG, "Error in obtaining ssl context");
                break;
            }
            print_peer_cert_info(ssl_ctx);
#endif
            break;
        default:
            ESP_LOGE(TAG, "Illegal state!");
            return;
    }
}
#endif

static const httpd_uri_t root = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = root_get_handler,
    // .user_ctx  = "Hello World!"

};
static const httpd_uri_t checkStateLight = {
    .uri       = "/",
    .method    = HTTP_POST,
    .handler   = set_light_state_handler,
    // .user_ctx  = "Hello World!"

};
// static const httpd_uri_t hello = {
//     .uri       = "/hello",
//     .method    = HTTP_GET,
//     .handler   = hello_get_handler,
//     /* Let's pass response string in user
//      * context to demonstrate it's usage */
//     .user_ctx  = "Hello World!"
// };


static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    // conf.lru_purge_enable = true;
    //设置成非安全模式，不需要服务器证书
    conf.transport_mode = HTTPD_SSL_TRANSPORT_INSECURE;

    extern const unsigned char servercert_start[] asm("_binary_server_pem_start");
    extern const unsigned char servercert_end[]   asm("_binary_server_pem_end");
    conf.servercert = servercert_start;
    conf.servercert_len = servercert_end - servercert_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_server_key_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_server_key_end");
    conf.prvtkey_pem = prvtkey_pem_start;
    conf.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;

    // extern const unsigned char client_pem_start[] asm("_binary_ca_pem_start");
    // extern const unsigned char client_pem_end[]   asm("_binary_ca_pem_end");
    // conf.client_verify_cert_pem = client_pem_start;
    // conf.client_verify_cert_len = client_pem_end - client_pem_start;

#if CONFIG_EXAMPLE_ENABLE_HTTPS_USER_CALLBACK
    conf.user_cb = https_server_user_callback;
#endif
    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }

    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");
    //应对各种请求
    httpd_register_uri_handler(server, &root);
    httpd_register_uri_handler(server, &checkStateLight);

    return server;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_ssl_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop https server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        *server = start_webserver();
    }
}



void app_main(void)
{
    static httpd_handle_t server = NULL;
// 打开WIFI等操作
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

// 设置舵机操作

    ESP_LOGI(TAG, "Create timer and operator");
    mcpwm_timer_handle_t timer = NULL;
    mcpwm_timer_config_t timer_config = {
        .group_id = 0,
        .clk_src = MCPWM_TIMER_CLK_SRC_DEFAULT,
        .resolution_hz = SERVO_TIMEBASE_RESOLUTION_HZ,
        .period_ticks = SERVO_TIMEBASE_PERIOD,
        .count_mode = MCPWM_TIMER_COUNT_MODE_UP,
    };
    ESP_ERROR_CHECK(mcpwm_new_timer(&timer_config, &timer));

    mcpwm_oper_handle_t oper = NULL;
    mcpwm_operator_config_t operator_config = {
        .group_id = 0, // operator must be in the same group to the timer
    };
    ESP_ERROR_CHECK(mcpwm_new_operator(&operator_config, &oper));

    ESP_LOGI(TAG, "Connect timer and operator");
    ESP_ERROR_CHECK(mcpwm_operator_connect_timer(oper, timer));

    ESP_LOGI(TAG, "Create comparator and generator from the operator");
    // static mcpwm_cmpr_handle_t comparator = NULL;
    mcpwm_comparator_config_t comparator_config = {
        .flags.update_cmp_on_tez = true,
    };
    ESP_ERROR_CHECK(mcpwm_new_comparator(oper, &comparator_config, &comparator));

    mcpwm_gen_handle_t generator = NULL;
    mcpwm_generator_config_t generator_config = {
        .gen_gpio_num = SERVO_PULSE_GPIO,
    };
    ESP_ERROR_CHECK(mcpwm_new_generator(oper, &generator_config, &generator));

    // set the initial compare value, so that the servo will spin to the center position
    ESP_ERROR_CHECK(mcpwm_comparator_set_compare_value(comparator, example_angle_to_compare(0)));

    ESP_LOGI(TAG, "Set generator action on timer and compare event");
    // go high on counter empty
    ESP_ERROR_CHECK(mcpwm_generator_set_action_on_timer_event(generator,
                                                              MCPWM_GEN_TIMER_EVENT_ACTION(MCPWM_TIMER_DIRECTION_UP, MCPWM_TIMER_EVENT_EMPTY, MCPWM_GEN_ACTION_HIGH)));
    // go low on compare threshold
    ESP_ERROR_CHECK(mcpwm_generator_set_action_on_compare_event(generator,
                                                                MCPWM_GEN_COMPARE_EVENT_ACTION(MCPWM_TIMER_DIRECTION_UP, comparator, MCPWM_GEN_ACTION_LOW)));

    ESP_LOGI(TAG, "Enable and start timer");
    ESP_ERROR_CHECK(mcpwm_timer_enable(timer));
    ESP_ERROR_CHECK(mcpwm_timer_start_stop(timer, MCPWM_TIMER_START_NO_STOP));


    /* Register event handlers to start server when Wi-Fi or Ethernet is connected,
     * and stop server when disconnection happens.
     */

#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
}
