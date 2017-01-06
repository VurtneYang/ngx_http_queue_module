#ifndef NGX_HTTP_QUEUE_MODULE_PUBLISHER_H_
#define NGX_HTTP_QUEUE_MODULE_PUBLISHER_H_
#include "ngx_http_queue_module.h"

static void		ngx_http_queue_module_unescape_uri(ngx_str_t *value);

static ngx_str_t *	ngx_http_queue_module_create_str(ngx_pool_t *pool, uint len);

static ngx_str_t *	ngx_http_queue_module_get_header(ngx_http_request_t *r, const ngx_str_t *header_name);

static void
ngx_http_queue_module_free_message_memory_locked(ngx_slab_pool_t *shpool, ngx_http_queue_module_msg_t *msg);

static void		ngx_http_queue_module_complex_value(ngx_http_request_t *r, ngx_http_complex_value_t *val, ngx_str_t *value);

ngx_http_queue_module_msg_t *	ngx_http_queue_module_convert_char_to_msg_on_shared_locked(ngx_http_queue_module_main_conf_t *mcf, u_char *data, size_t len, ngx_str_t *event_id, ngx_str_t *event_type, ngx_pool_t *temp_pool);

ngx_http_queue_module_channel_t *	ngx_http_queue_module_add_msg_to_channel(ngx_http_request_t *r, ngx_str_t *id, ngx_str_t *key, u_char *text, size_t len, ngx_str_t *event_id, ngx_str_t *event_type, ngx_pool_t *temp_pool);

static ngx_int_t ngx_http_queue_module_publisher_handle_after_read_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler);

static void ngx_http_queue_module_publisher_body_handler(ngx_http_request_t *r);

static ngx_int_t	ngx_http_publisher_handler(ngx_http_request_t *r);

#endif
