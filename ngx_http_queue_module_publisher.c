#include "ngx_http_queue_module_publisher.h"

static ngx_str_t *
ngx_http_queue_module_create_str(ngx_pool_t *pool, uint len)
{
    ngx_str_t *aux = (ngx_str_t *) ngx_pcalloc(pool, sizeof(ngx_str_t) + len + 1);
    if (aux != NULL) {
        aux->data = (u_char *) (aux + 1);
        aux->len = len;
        ngx_memset(aux->data, '\0', len + 1);
    }
    return aux;
}

static ngx_str_t *
ngx_http_queue_module_get_header(ngx_http_request_t *r, const ngx_str_t *header_name)
{
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    ngx_str_t                   *aux = NULL;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if ((h[i].key.len == header_name->len) && (ngx_strncasecmp(h[i].key.data, header_name->data, header_name->len) == 0)) {
            aux = ngx_http_queue_module_create_str(r->pool, h[i].value.len);
            if (aux != NULL) {
                ngx_memcpy(aux->data, h[i].value.data, h[i].value.len);
            }
            break;
        }
    }

    return aux;
}
 
static void
ngx_http_queue_module_free_message_memory_locked(ngx_slab_pool_t *shpool, ngx_http_queue_module_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->raw.data != NULL) ngx_slab_free_locked(shpool, msg->raw.data);
    if (msg->event_id != NULL) ngx_slab_free_locked(shpool, msg->event_id);
    if (msg->event_type != NULL) ngx_slab_free_locked(shpool, msg->event_type);
    ngx_slab_free_locked(shpool, msg);
	
}

ngx_http_queue_module_msg_t *
ngx_http_queue_module_convert_char_to_msg_on_shared_locked(ngx_http_queue_module_main_conf_t *mcf, u_char *data, size_t len, ngx_str_t *event_id, ngx_str_t *event_type, ngx_pool_t *temp_pool)
{
    ngx_slab_pool_t                           *shpool = mcf->shpool;
    ngx_http_queue_module_msg_t                *msg;

    if ((msg = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_queue_module_msg_t))) == NULL) { 
		return NULL;
    }

    msg->event_id = NULL;
    msg->event_type = NULL;
    msg->expires = 0;
    ngx_queue_init(&msg->queue);

    if ((msg->raw.data = ngx_slab_alloc_locked(shpool, len + 1)) == NULL) { 
		ngx_http_queue_module_free_message_memory_locked(shpool, msg);
        return NULL;
    }

    msg->raw.len = len;
	ngx_memcpy(msg->raw.data, data, len);
    msg->raw.data[msg->raw.len] = '\0';

    return msg;
}

ngx_http_queue_module_channel_t *
ngx_http_queue_module_add_msg_to_channel(ngx_http_request_t *r, ngx_str_t *id,  ngx_str_t *key, u_char *text, size_t len, ngx_str_t *event_id, ngx_str_t *event_type, ngx_pool_t *temp_pool)
{
	ngx_http_queue_module_main_conf_t       *mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);
    ngx_http_queue_module_loc_conf_t        *cf = ngx_http_get_module_loc_conf(r, ngx_http_queue_module);
    ngx_http_queue_module_shm_data_t        *data = mcf->shm_data;
   	ngx_slab_pool_t                         *shpool = mcf->shpool;
	ngx_http_queue_module_channel_t         *channel;
    ngx_http_queue_module_leaf_t            *leaf;
    ngx_http_queue_module_msg_t             *msg;
	ngx_http_queue_module_msg_t             *message;

    ngx_shmtx_lock(&shpool->mutex);

	channel = ngx_http_queue_module_find_channel(id, r->connection->log, mcf);
    if (channel == NULL) {
        ngx_shmtx_unlock(&(shpool)->mutex);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: find channel failed and released lock");
        return NULL;
    }
		
	msg = ngx_http_queue_module_convert_char_to_msg_on_shared_locked(mcf, text, len, event_id, event_type, temp_pool);
    if (msg == NULL) {   
		ngx_shmtx_unlock(&(shpool)->mutex); 
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: allcate memory for msg failed and released lock");
		return NULL;
    }

	if (channel && 0 == key->len)
	{
		if ((mcf->max_messages_stored_per_channel != NGX_CONF_UNSET_UINT) && (mcf->max_messages_stored_per_channel == channel->stored_messages)) {
	        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: stored messages equals maximum value and released lock");
			ngx_shmtx_unlock(&shpool->mutex);	
			return NULL;
		}

		if ((leaf = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_queue_module_leaf_t))) == NULL) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: allcate memory for leaf failed and released lock");
			ngx_shmtx_unlock(&shpool->mutex);
         	return NULL;
     	}
			
		ngx_queue_init(&leaf->message_pointer);
		leaf->key.len = 0;
		leaf->key.data = 0x0;
		leaf->stored_flag = 1;
		ngx_queue_insert_tail(&leaf->message_pointer, &msg->queue);
		ngx_queue_insert_tail(&channel->leafs_queue, &leaf->queue);
	    leaf->queue_sentinel = &channel->leafs_queue;
		cf->stored_messages++;
		channel->stored_messages++;
        data->stored_messages++;
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: released lock");
		ngx_shmtx_unlock(&shpool->mutex);
		return channel;
	}	

    leaf = ngx_http_queue_module_find_leaf(id, key, r->connection->log, mcf);
    if (leaf == NULL) {
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: find leaf failed and released lock");
        ngx_shmtx_unlock(&(shpool)->mutex);
        return NULL;
    }
	
	if (0 == leaf->stored_flag)
	{
		cf->stored_messages++;
		leaf->stored_flag = 1;

    	if (cf->stored_messages) {
			if (channel->stored_messages >= mcf->max_messages_stored_per_channel)
			{
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: stored messages equals maximum value and released lock");
				ngx_shmtx_unlock(&shpool->mutex);
				return NULL;
			}
			else
			{
		 		ngx_queue_insert_tail(&leaf->message_pointer, &msg->queue);
        		channel->stored_messages++;
        		data->stored_messages++;
			}	
		}
	}
	else if (1 == leaf->stored_flag)
	{	
		ngx_queue_t                *cur;
   	    cur = &leaf->message_pointer;
        cur = ngx_queue_next(cur);
		if ((cur != NULL) && (cur != &leaf->message_pointer)) 
        {       
        	message = (ngx_http_queue_module_msg_t *) ngx_queue_data(cur, ngx_http_queue_module_msg_t, queue);
            if (message)
            {   
                ngx_queue_remove(cur);
                ngx_http_queue_module_free_message_memory_locked(shpool, message);
                ngx_queue_insert_tail(&leaf->message_pointer, &msg->queue); 
                    
            }
        }
	}
	else
	{
		ngx_shmtx_unlock(&shpool->mutex);
		return NULL;
	}

	ngx_shmtx_unlock(&shpool->mutex);
	return channel;
}

/**/

static void
ngx_http_queue_module_unescape_uri(ngx_str_t *value)
{
    u_char                                         *dst, *src;

    if (value->len) {
        dst = value->data;
        src = value->data;
        ngx_unescape_uri(&dst, &src, value->len, NGX_UNESCAPE_URI);
        if (dst < src) {
            *dst = '\0';
            value->len = dst - value->data;
        }
    }
}


static void
ngx_http_queue_module_complex_value(ngx_http_request_t *r, ngx_http_complex_value_t *val, ngx_str_t *value)
{
    ngx_http_complex_value(r, val, value);
    ngx_http_queue_module_unescape_uri(value);
}

static ngx_int_t
ngx_http_queue_module_publisher_handle_after_read_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler)
{
    ngx_int_t                           rc;

    r->request_body_in_single_buf = 0;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 0;
    r->request_body_file_log_level = 0;

    rc = ngx_http_read_client_request_body(r, post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static void
ngx_http_queue_module_publisher_body_handler(ngx_http_request_t *r)
{
    // check if body message wasn't empty
    if (r->headers_in.content_length_n <= 0) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: Post request was sent with no message");
        //ngx_http_queue_module_send_only_header_response_and_finalize(r, NGX_HTTP_BAD_REQUEST, &NGX_HTTP_QUEUE_MODULE_EMPTY_POST_REQUEST_MESSAGE);
        return;
    }

}

static ngx_int_t
ngx_http_publisher_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_buf_t *buf = NULL;
	ngx_chain_t							   *chain;
	ngx_str_t                              *event_id, *event_type;
	ngx_chain_t out;
	ngx_str_t text = ngx_null_string;
	ssize_t n;
	off_t   len = 0;

	if(!(r->method & (NGX_HTTP_HEAD|NGX_HTTP_GET|NGX_HTTP_POST)))
    {
		return NGX_HTTP_NOT_ALLOWED;
    }	

	ngx_http_queue_module_loc_conf_t                *cf = ngx_http_get_module_loc_conf(r, ngx_http_queue_module);	
	ngx_http_queue_module_main_conf_t   *mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);	

	ngx_str_t                                       id = ngx_null_string;
	ngx_str_t 										key = ngx_null_string;
	ngx_http_queue_module_channel_t                 *channel;

	ngx_http_queue_module_complex_value(r, cf->channel_id, &id);
	ngx_http_queue_module_complex_value(r, cf->channel_key, &key);
	if (0 == id.len || NULL == r)
    	return 406;
	
	ngx_http_queue_module_publisher_handle_after_read_body(r, ngx_http_queue_module_publisher_body_handler);

    buf = ngx_create_temp_buf(r->pool, r->headers_in.content_length_n + 1);
	if (buf != NULL && r->request_body->bufs) 
	{	
		ngx_memset(buf->start, '\0', r->headers_in.content_length_n + 1);

		chain = r->request_body->bufs;
		while ((NULL != chain)&&(NULL != chain->buf)) {
		
		len = ngx_buf_size(chain->buf);

		if (len >= r->headers_in.content_length_n) {
        	buf->start = buf->pos;
        	buf->last = buf->pos;
           	len = r->headers_in.content_length_n;
        }

        if (chain->buf->in_file) {
                n = ngx_read_file(chain->buf->file, buf->start, len, 0);
                if (n == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "queue module: cannot read file with request body");
                    return 406;
                }
                buf->last = buf->last + len;
                ngx_delete_file(chain->buf->file->name.data);
                chain->buf->file->fd = NGX_INVALID_FILE;
            } else {
                buf->last = ngx_copy(buf->start, chain->buf->pos, len);
            }

            chain = chain->next;
            buf->start = buf->last;
      	}

	 
		event_id = ngx_http_queue_module_get_header(r, &NGX_HTTP_QUEUE_MODULE_HEADER_EVENT_ID);
    	event_type = ngx_http_queue_module_get_header(r, &NGX_HTTP_QUEUE_MODULE_HEADER_EVENT_TYPE);

		if (NGX_HTTP_QUEUE_MODULE_NUMBER_OF_CHANNELS_EXCEEDED == ngx_http_queue_module_get_channel(&id, r->connection->log, cf, mcf))
			return 406;

		if (0 != key.len)
			if (NGX_HTTP_QUEUE_MODULE_NUMBER_OF_MESSAGES_EXCEEDED == ngx_http_queue_module_get_leaf(&id, &key, r->connection->log, cf, mcf))
	        	return 406;
		
		channel = ngx_http_queue_module_add_msg_to_channel(r, &id, &key, buf->pos, ngx_buf_size(buf), event_id, event_type, r->pool);
		if (channel == NULL)
  			return 406;

		mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);
	
		r->headers_out.content_type.len = sizeof(NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data)+2;
    	r->headers_out.content_type.data = (u_char *) NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data;
    	r->headers_out.status = NGX_HTTP_OK;
    	r->headers_out.content_length_n = ngx_buf_size(buf);
	
	    out = *ngx_http_queue_module_get_buf(r);
       	out.buf = buf;
		buf->last_buf = 0;
      	buf->last_in_chain = 1;
      	buf->flush = 1;
      	buf->memory = 0;
        out.next = NULL;

		rc = ngx_http_send_header(r);
    	rc = ngx_http_output_filter(r, &out);
		return rc;
	}
    else {
	
	  r->headers_out.content_type.len = sizeof(NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data)+2;
      r->headers_out.content_type.data = (u_char *) NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data;
      r->headers_out.status = NGX_HTTP_OK;
      r->headers_out.content_length_n = text.len;

	  if (ngx_http_queue_module_get_buf(r) == NULL)
	  	return NGX_ERROR;
	
	  out = *ngx_http_queue_module_get_buf(r);
	  buf = out.buf; 
      buf->last_buf = 0;
      buf->last_in_chain = 1;
      buf->flush = 1;
      buf->memory = 0;
      buf->pos =  (u_char*) text.data;
      buf->start = buf->pos;
	  buf->end = buf->pos + text.len;
      buf->last = buf->end;
      out.next = NULL;
	
      rc = ngx_http_send_header(r);
      rc = ngx_http_output_filter(r, &out);
      return rc;

	}
}
