#include "ngx_http_queue_module_statistics.h"

static ngx_str_t *
ngx_http_queue_module_channel_info_formatted(ngx_pool_t *pool, const ngx_str_t *format, ngx_str_t *id, ngx_uint_t stored_messages)
{
    ngx_str_t      *text;
    ngx_uint_t      len;

    if ((format == NULL) || (id == NULL)) {
        return NULL;
    }

    len = 3*NGX_INT_T_LEN + format->len + id->len - 11;// minus 11 sprintf

    if ((text = ngx_http_queue_module_create_str(pool, len)) == NULL) {
        return NULL;
    }

    ngx_sprintf(text->data, (char *) format->data, id->data, stored_messages);
    text->len = ngx_strlen(text->data);

    return text;
}

static ngx_int_t
ngx_http_queue_module_send_response_text(ngx_http_request_t *r, const u_char *text, uint len, ngx_flag_t last_buffer)
{
    ngx_buf_t     *b;
    ngx_chain_t   *out;

    if ((text == NULL) || (r->connection->error)) {
        return NGX_ERROR;
    }

    out = ngx_http_queue_module_get_buf(r);
    if (out == NULL) {
        return NGX_ERROR;
    }

    b = out->buf;

    b->last_buf = last_buffer;
    b->last_in_chain = 1;
    b->flush = 1;
    b->memory = 1;
    b->pos = (u_char *) text;
    b->start = b->pos;
    b->end = b->pos + len;
    b->last = b->end;

    out->next = NULL;

    return ngx_http_output_filter(r, out);
}

static ngx_http_queue_module_content_subtype_t *
ngx_http_queue_module_match_channel_info_format_and_content_type(ngx_http_request_t *r, ngx_uint_t default_subtype)
{
    ngx_uint_t      i;
    ngx_http_queue_module_content_subtype_t *subtype = &subtypes[default_subtype];

    if (r->headers_in.accept) {
        u_char     *cur = r->headers_in.accept->value.data;
        size_t      rem = 0;

        while ((cur != NULL) && (cur = ngx_strnstr(cur, "/", r->headers_in.accept->value.len)) != NULL) {
            cur = cur + 1;
            rem = r->headers_in.accept->value.len - (r->headers_in.accept->value.data - cur);

            for(i=0; i<(sizeof(subtypes) / sizeof(ngx_http_queue_module_content_subtype_t)); i++) {
                if (ngx_strncmp(cur, subtypes[i].subtype, rem < subtypes[i].len ? rem : subtypes[i].len) == 0) {
                    subtype = &subtypes[i];
  					cur = NULL;
                    break;
                }
            }
        }
    }

    return subtype;
}

static ngx_int_t
ngx_http_queue_module_send_response_channels_info(ngx_http_request_t *r, ngx_queue_t *queue_channel_info) 
{
    ngx_int_t                                 rc, content_len = 0;
    ngx_chain_t                              *chain, *first = NULL, *last = NULL;
    ngx_str_t                                *text, *header_response;
    ngx_queue_t                              *cur, *next;
    ngx_http_queue_module_main_conf_t         *mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);
    ngx_http_queue_module_shm_data_t          *data = mcf->shm_data;
	ngx_http_queue_module_content_subtype_t   *subtype = ngx_http_queue_module_match_channel_info_format_and_content_type(r, 1);
	
	const ngx_str_t *format;
    const ngx_str_t *head = subtype->format_group_head;
    const ngx_str_t *tail = subtype->format_group_tail;

	cur = ngx_queue_head(queue_channel_info);
    while (cur != queue_channel_info) {
        next = ngx_queue_next(cur);
        ngx_http_queue_module_channel_info_t *channel_info = (ngx_http_queue_module_channel_info_t *) cur;
        if ((chain = ngx_http_queue_module_get_buf(r)) == NULL) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: unable to allocate memory for response channels info");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
		
		format = (next != queue_channel_info) ? subtype->format_group_item : subtype->format_group_last_item;

        if ((text = ngx_http_queue_module_channel_info_formatted(r->pool, format, &channel_info->id, channel_info->stored_messages)) == NULL) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: unable to allocate memory to format channel info");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        chain->buf->last_buf = 0;
        chain->buf->memory = 1;
        chain->buf->pos = text->data;
        chain->buf->last = text->data + text->len;
        chain->buf->start = chain->buf->pos;
        chain->buf->end = chain->buf->last;

        content_len += text->len;

        if (first == NULL) {
            first = chain;
        }

        if (last != NULL) {
            last->next = chain;
        }

        last = chain;
        cur = next;
    }
	
	if ((header_response = ngx_http_queue_module_create_str(r->pool, head->len + NGX_INT_T_LEN)) == NULL) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: unable to allocate memory for response channels info");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(header_response->data, (char *) head->data, data->stored_channels);
    header_response->len = ngx_strlen(header_response->data);

    content_len += header_response->len + tail->len;

    r->headers_out.content_type_len = subtype->content_type->len;
   	r->headers_out.content_type  = * subtype->content_type;
    r->headers_out.content_length_n = content_len;
    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
	
	ngx_http_queue_module_send_response_text(r, header_response->data, header_response->len,0);
	
	if (first != NULL) {
        ngx_http_output_filter(r, first);
    }
	
	return ngx_http_queue_module_send_response_text(r, tail->data, tail->len, 1);
}

static ngx_int_t
ngx_http_queue_module_send_response_all_channels_info_detailed(ngx_http_request_t *r)
{
    ngx_http_queue_module_main_conf_t         *mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);
    ngx_queue_t                               queue_channel_info;
    ngx_http_queue_module_shm_data_t          *data = mcf->shm_data;
    ngx_slab_pool_t                          *shpool = mcf->shpool;
    ngx_queue_t                              *cur = &data->channels_queue;
    ngx_http_queue_module_channel_t           *channel;
	ngx_uint_t								  sum = 0;

    ngx_queue_init(&queue_channel_info);

    ngx_shmtx_lock(&shpool->mutex);
	while ((cur = ngx_queue_next(cur)) && (cur != NULL) && (cur != &data->channels_queue)) 
    {
		channel = ngx_queue_data(cur, ngx_http_queue_module_channel_t, queue);
		ngx_http_queue_module_channel_info_t *channel_info;

        if ((channel_info = ngx_pcalloc(r->pool, sizeof(ngx_http_queue_module_channel_info_t))) != NULL)
		{       
			channel_info->id.data = channel->id.data;
            channel_info->id.len = channel->id.len;
            channel_info->stored_messages = channel->stored_messages;
            ngx_queue_insert_tail(&queue_channel_info, &channel_info->queue);
        }
		
		ngx_queue_t 						*cus = &channel->leafs_queue;
		while ((cus = ngx_queue_next(cus)) && (cus != NULL) && (cus != &channel->leafs_queue))
			sum++;
    
	}
    ngx_shmtx_unlock(&shpool->mutex);

    return ngx_http_queue_module_send_response_channels_info(r, &queue_channel_info);
}

