#include "ngx_http_queue_module_subscriber.h"

ngx_chain_t *
ngx_http_queue_module_get_buf(ngx_http_request_t *r)
{
    ngx_http_queue_module_ctx_t      *ctx = NULL;
    ngx_chain_t                            *out = NULL;

    if ((ctx = ngx_http_get_module_ctx(r, ngx_http_queue_module)) != NULL) {
        out = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (out != NULL) {
            out->buf->tag = (ngx_buf_tag_t) &ngx_http_queue_module;
        }
    } else {
        out = (ngx_chain_t *) ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
        if (out == NULL) {
            return NULL;
        }

        out->buf = ngx_calloc_buf(r->pool);
        if (out->buf == NULL) {
            return NULL;
        }
    }

    return out;
}

static ngx_int_t
ngx_http_subscriber_handler(ngx_http_request_t *r)
{
	 ngx_http_queue_module_leaf_t                 	 *leaf = NULL;
	 ngx_http_queue_module_channel_t                 *channel = NULL;
     ngx_http_queue_module_loc_conf_t                *cf = ngx_http_get_module_loc_conf(r, ngx_http_queue_module);
     ngx_http_queue_module_main_conf_t   *mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);    
	 ngx_queue_t                *cur;
	 ngx_http_queue_module_msg_t *message;
	 ngx_http_queue_module_shm_data_t        *data = mcf->shm_data;
	 ngx_slab_pool_t                        *shpool = mcf->shpool;
	 ngx_str_t                                       id = ngx_null_string;
	 ngx_str_t                                       key = ngx_null_string;
	 ngx_http_queue_module_complex_value(r, cf->channel_id, &id);
	 ngx_http_queue_module_complex_value(r, cf->channel_key, &key);
     ngx_int_t rc = NGX_OK;
     ngx_buf_t  *b;
     ngx_chain_t  *out;
     u_char *text = NULL;
	 uint   len = 0;
	 if (0 == id.len || NULL == r)
	 	return 406;

     b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
     if(b == NULL)
     {
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Failed to allocate response buffer.");
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
		
	 channel = ngx_http_queue_module_find_channel(&id, r->connection->log, mcf);
    
	 if (channel && channel->stored_messages) 
	 {
		out = ngx_http_queue_module_get_buf(r);
		if (out == NULL)
        	return NGX_ERROR;
        b = out->buf;

     	leaf = ngx_http_queue_module_find_leaf(&id, &key, r->connection->log, mcf);
		if(leaf)
		{
			ngx_shmtx_lock(&shpool->mutex);
			cur = &leaf->message_pointer;
			cur = ngx_queue_next(cur);
	
			if ((cur != NULL) && (cur != &leaf->message_pointer)) 
			{
				message = (ngx_http_queue_module_msg_t *) ngx_queue_data(cur, ngx_http_queue_module_msg_t, queue);
			    
				if (message && channel->stored_messages > 0 && 1 == leaf->stored_flag)
				{
					text = message->raw.data;	
                    if ((text == NULL) || (r->connection->error))
                          return NGX_ERROR;
					
					if (0 != leaf->key.len)
					{
						ngx_rbtree_delete(&channel->tree, &leaf->node);
						ngx_slab_free_locked(shpool, leaf->key.data);
					}
					
					leaf->stored_flag = 0;
					ngx_queue_remove(&leaf->queue);
					ngx_slab_free_locked(shpool, leaf);

					len = message->raw.len;
					ngx_http_queue_module_free_message_memory_locked(shpool, message);
					cf->stored_messages--;
            		channel->stored_messages--;
            		data->stored_messages--;
            		
     				b->memory = 1; 
            	}
				else 
     				b->memory = 0;
			}
	
		}
		else if(0 == key.len)
		{
			ngx_shmtx_lock(&shpool->mutex);
			cur = &channel->leafs_queue;
        	cur = ngx_queue_next(cur);

        	if ((cur != NULL) && (cur != &channel->leafs_queue))
            {
            	leaf = (ngx_http_queue_module_leaf_t *) ngx_queue_data(cur, ngx_http_queue_module_leaf_t, queue);
            	message = (ngx_http_queue_module_msg_t *) ngx_queue_data(ngx_queue_next(&leaf->message_pointer), ngx_http_queue_module_msg_t, queue);
            	if (message && channel->stored_messages > 0 && 1 == leaf->stored_flag)
            	{
                	text = message->raw.data;	
				    if ((text == NULL) || (r->connection->error))
                        return NGX_ERROR;

					if (0 != leaf->key.len)
					{
                		ngx_rbtree_delete(&channel->tree, &leaf->node);
                		ngx_slab_free_locked(shpool, leaf->key.data);
					}
					
					leaf->stored_flag = 0;
					ngx_queue_remove(&leaf->queue);	
					ngx_slab_free_locked(shpool, leaf);

					len = message->raw.len;
					ngx_http_queue_module_free_message_memory_locked(shpool, message);
					cf->stored_messages--;
                    channel->stored_messages--;
                    data->stored_messages--;
		
                    b->memory = 1;
                }
                else
                    b->memory = 0;
        	}

		}
		else
			 b->memory = 0;

		ngx_shmtx_unlock(&shpool->mutex);
		r->headers_out.content_type.len = sizeof(NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data) +2;
    	r->headers_out.content_type.data = (u_char *) NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data;
    	r->headers_out.status = NGX_HTTP_OK;
    	r->headers_out.content_length_n = len;

     	b->last_buf = 0;
     	b->last_in_chain = 1;
     	b->flush = 1;
     	b->pos = (u_char *) text;
     	b->start = b->pos;
     	b->end = b->pos + len;
     	b->last = b->end;
     	out->next = NULL;
     
		rc = ngx_http_send_header(r);
		rc = ngx_http_output_filter(r, out);
   		return rc;

     }
	 else
		return 406;
}

static ngx_int_t
ngx_http_subscriber_delete_handler(ngx_http_request_t *r)
{
	ngx_http_queue_module_channel_t                 *channel = NULL;
	ngx_http_queue_module_leaf_t                    *leaf = NULL;
	ngx_http_queue_module_loc_conf_t                *cf = ngx_http_get_module_loc_conf(r, ngx_http_queue_module);
    ngx_http_queue_module_main_conf_t   *mcf = ngx_http_get_module_main_conf(r, ngx_http_queue_module);
	ngx_slab_pool_t                        *shpool = mcf->shpool;
	ngx_http_queue_module_shm_data_t    *data = mcf->shm_data;
    ngx_str_t                                       id = ngx_null_string;
    ngx_http_queue_module_complex_value(r, cf->channel_id, &id);
	ngx_queue_t                *cur;
	ngx_http_queue_module_msg_t *message;
    ngx_int_t rc = NGX_OK;
	ngx_buf_t  *b;
	ngx_chain_t  *out;
    u_char *text = NULL;
	uint   len = 0;
	if (0 == id.len || NULL == r)      
		return 406;
	channel = ngx_http_queue_module_find_channel(&id, r->connection->log, mcf);

	if (channel)
	{	
		ngx_shmtx_lock(&shpool->mutex);
		cur = &channel->leafs_queue;
		cur = ngx_queue_next(cur);
		out = ngx_http_queue_module_get_buf(r);
        if (out == NULL) 
			return NGX_ERROR;
		b = out->buf; 
	
		while ((cur != NULL) && (cur != &channel->leafs_queue)) 
		{
			leaf = (ngx_http_queue_module_leaf_t *) ngx_queue_data(cur, ngx_http_queue_module_leaf_t, queue);
			message = (ngx_http_queue_module_msg_t *) ngx_queue_data(ngx_queue_next(&leaf->message_pointer), ngx_http_queue_module_msg_t, queue);
			cur = ngx_queue_next(cur);
			if (message && channel->stored_messages > 0)
			{
				ngx_http_queue_module_free_message_memory_locked(shpool, message);
				if (0 != leaf->key.len)
				{
					ngx_rbtree_delete(&channel->tree, &leaf->node);
					ngx_slab_free_locked(shpool, leaf->key.data);
				}
			}
			ngx_queue_remove(&leaf->queue);
			ngx_slab_free_locked(shpool, leaf);
		}

		ngx_rbtree_delete(&data->tree, &channel->node);
		ngx_queue_remove(&channel->queue);
		data->stored_messages = data->stored_messages - channel->stored_messages;
		channel->stored_messages = 0;
		ngx_slab_free_locked(shpool, channel->id.data);
		ngx_slab_free_locked(shpool, channel->tree.root);
		ngx_slab_free_locked(shpool, channel);
		data->stored_channels--;

		ngx_shmtx_unlock(&shpool->mutex);
		
	 	r->headers_out.content_type.len = sizeof(NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data) +2;
     	r->headers_out.content_type.data = (u_char *) NGX_HTTP_QUEUE_MODULE_CONTENT_TYPE_PLAIN.data;
     	r->headers_out.status = NGX_HTTP_OK;
     	r->headers_out.content_length_n = len;
	
	 	out = ngx_http_queue_module_get_buf(r);
	 	b = out->buf;
     	b->last_buf = 0;
     	b->last_in_chain = 1;
     	b->flush = 1;
     	b->pos = (u_char *) text;
     	b->start = b->pos;
     	b->end = b->pos + len;
     	b->last = b->end;
     	out->next = NULL;

     	rc = ngx_http_send_header(r);
        rc = ngx_http_output_filter(r, out);
		return rc;
	}
	else
		return 406;
}
