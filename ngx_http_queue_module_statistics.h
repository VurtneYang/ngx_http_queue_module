#ifndef NGX_HTTP_QUEUE_MODULE_STATISTICS_H_
#define NGX_HTTP_QUEUE_MODULE_STATISTICS_H_
#include "ngx_http_queue_module.h"

#define  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_PLAIN_PATTERN "channel: %s" CRLF"stored_messages: %ui"
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN = ngx_string("text/plain");
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_PLAIN = ngx_string(NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_PLAIN_PATTERN CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_HEAD_PLAIN = ngx_string("channels: %ui, infos: " CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_TAIL_PLAIN = ngx_string(CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_ITEM_PLAIN = ngx_string(NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_PLAIN_PATTERN "," CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_LAST_ITEM_PLAIN = ngx_string(NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_PLAIN_PATTERN);

#define  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_JSON_PATTERN "{\"channel\": \"%s\", \"stored_messages\": \"%ui\"}"
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_JSON = ngx_string("application/json");
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_JSON = ngx_string(NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_JSON_PATTERN CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_HEAD_JSON = ngx_string("{\"channels\": \"%ui\", \"infos\": [" CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_TAIL_JSON = ngx_string("]}" CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_ITEM_JSON = ngx_string(NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_JSON_PATTERN "," CRLF);
static ngx_str_t  NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_LAST_ITEM_JSON = ngx_string(NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_JSON_PATTERN CRLF);

static ngx_http_queue_module_content_subtype_t subtypes[] = {
    { "plain" , 5,
            &NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_PLAIN,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_HEAD_PLAIN,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_ITEM_PLAIN,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_LAST_ITEM_PLAIN,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_TAIL_PLAIN },
    { "json"  , 4,
            &NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_JSON,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_JSON,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_HEAD_JSON,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_ITEM_JSON,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_LAST_ITEM_JSON,
            &NGX_HTTP_QUEUE_MODULE_CHANNEL_INFO_GROUP_TAIL_JSON }
};

static ngx_str_t *	ngx_http_queue_module_channel_info_formatted(ngx_pool_t *pool, const ngx_str_t *format, ngx_str_t *id, ngx_uint_t stored_messages);

static ngx_int_t	ngx_http_queue_module_send_response_text(ngx_http_request_t *r, const u_char *text, uint len, ngx_flag_t last_buffer);

static ngx_http_queue_module_content_subtype_t *	ngx_http_queue_module_match_channel_info_format_and_content_type(ngx_http_request_t *r, ngx_uint_t default_subtype);

static ngx_int_t ngx_http_queue_module_send_response_channels_info(ngx_http_request_t *r, ngx_queue_t *queue_channel_info);

static ngx_int_t	ngx_http_queue_module_send_response_all_channels_info_detailed(ngx_http_request_t *r);

#endif
