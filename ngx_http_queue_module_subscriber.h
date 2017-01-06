#ifndef NGX_HTTP_QUEUE_MODULE_SUBSCRIBER_H_
#define NGX_HTTP_QUEUE_MODULE_SUBSCRIBER_H_
#include "ngx_http_queue_module.h"

ngx_chain_t *	ngx_http_queue_module_get_buf(ngx_http_request_t *r);
static ngx_int_t ngx_http_subscriber_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_subscriber_delete_handler(ngx_http_request_t *r);

#endif
