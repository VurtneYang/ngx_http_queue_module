#include "ngx_http_queue_module.h"

static void *ngx_http_queue_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_queue_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_get_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_delete_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_statis_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_queue_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 
static ngx_command_t  ngx_http_queue_commands[] = {
    { ngx_string("add_queue"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,        
      ngx_http_queue_setup,
	  0,                 
      0,
      NULL
     },
	
	{ ngx_string("get_queue"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_get_setup,
	  0,
      0,
	  NULL
    },
			
	{ ngx_string("delete_queue"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_delete_setup,
      0,
	  0,
      NULL },	

	{ ngx_string("statis_queue"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_statis_setup,
	  0,
      0,
      NULL },

	{ ngx_string("queue_shm_zone"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_http_queue_shared_dict,
      0,
      0,
      NULL },

	{ ngx_string("max_number_of_channels"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_queue_module_main_conf_t, max_number_of_channels),
	  NULL },
 
	{ ngx_string("max_messages_stored_per_channel"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_queue_module_main_conf_t, max_messages_stored_per_channel),
      NULL },

    { ngx_string("channel_id"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1, 
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_queue_module_loc_conf_t, channel_id),
      NULL },
    
	{ ngx_string("channel_key"),
 	  NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
	  ngx_http_set_complex_value_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_queue_module_loc_conf_t, channel_key),
	  NULL },
	
      ngx_null_command
};
 
/* Http context of the module */
static ngx_http_module_t  ngx_http_queue_module_ctx = {
    ngx_http_queue_module_preconfig,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
 
    ngx_http_queue_module_create_main_conf,                                  /* create main configuration */
    ngx_http_queue_module_init_main_conf,                                  /* init main configuration */
 
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
 
    ngx_http_queue_create_loc_conf,            /* create location configration */
    NULL						             /* merge location configration */
};

ngx_module_t  ngx_http_queue_module = {
    NGX_MODULE_V1,
    &ngx_http_queue_module_ctx,              /* module context */
    ngx_http_queue_commands,                /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#include "ngx_http_queue_module_publisher.h"
#include "ngx_http_queue_module_subscriber.h"
#include "ngx_http_queue_module_statistics.h"
#include "ngx_http_queue_module_rbtree_util.h"
#include "ngx_http_queue_module_publisher.c"
#include "ngx_http_queue_module_subscriber.c"
#include "ngx_http_queue_module_statistics.c"
#include "ngx_http_queue_module_rbtree_util.c"

static void *
ngx_http_queue_module_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_queue_module_main_conf_t    *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_queue_module_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }
	mcf->enabled = 0;
	mcf->max_number_of_channels = NGX_CONF_UNSET_UINT;
	mcf->max_messages_stored_per_channel = NGX_CONF_UNSET_UINT;
	
    return mcf;
}

/* Handler function */
static ngx_int_t
ngx_http_queue_handler(ngx_http_request_t *r)
{
	r->main->count--;
	return ngx_http_publisher_handler(r);
}

static ngx_int_t
ngx_http_get_handler(ngx_http_request_t *r)
{
	return  ngx_http_subscriber_handler(r);
}

static ngx_int_t
ngx_http_delete_handler(ngx_http_request_t *r) 
{
	return ngx_http_subscriber_delete_handler(r);
}

static ngx_int_t
ngx_http_statis_handler(ngx_http_request_t *r)
{
	return ngx_http_queue_module_send_response_all_channels_info_detailed(r);
}

static char *
ngx_http_queue_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{  
	ngx_http_core_loc_conf_t  * clcf;
	ngx_http_queue_module_main_conf_t    *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_queue_module);
	mcf->enabled = 1;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_queue_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
   
    return NGX_CONF_OK;
}

static char *
ngx_http_get_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{	
	ngx_http_core_loc_conf_t  * clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_get_handler;
	ngx_conf_set_str_slot(cf, cmd, conf);

	return NGX_CONF_OK;
}

static char *
ngx_http_delete_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{	
	ngx_http_core_loc_conf_t  * clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_delete_handler;
	ngx_conf_set_str_slot(cf, cmd, conf);

	return NGX_CONF_OK;
}

static char *
ngx_http_statis_setup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{	
	ngx_http_core_loc_conf_t  * clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_statis_handler;
	ngx_conf_set_str_slot(cf, cmd, conf);

	return NGX_CONF_OK;
}

static void *
ngx_http_queue_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_queue_module_loc_conf_t  *conf;
 
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_queue_module_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_queue_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t	*value,*name;
	size_t	shm_size;

	size_t                               shm_size_limit = 32 * ngx_pagesize;
	ngx_http_queue_module_main_conf_t    *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_queue_module);


	value = cf->args->elts;
	shm_size = ngx_align(ngx_parse_size(&value[1]), ngx_pagesize);
	if (shm_size < shm_size_limit) {
		return NGX_CONF_ERROR;
	}
		
	name = (cf->args->nelts > 2) ? &value[2] : &ngx_http_queue_module_shm_name;
	if ((ngx_http_queue_module_global_shm_zone != NULL) && (ngx_http_queue_module_global_shm_zone->data != NULL)) {
		ngx_http_queue_module_global_shm_data_t *global_data = (ngx_http_queue_module_global_shm_data_t *) ngx_http_queue_module_global_shm_zone->data;
        ngx_queue_t                            *cur = &global_data->shm_datas_queue;		
		
		while ((cur = ngx_queue_next(cur)) != &global_data->shm_datas_queue) {
            ngx_http_queue_module_shm_data_t *data = ngx_queue_data(cur, ngx_http_queue_module_shm_data_t, shm_datas_queue);
            if ((name->len == data->shm_zone->shm.name.len) &&
                (ngx_strncmp(name->data, data->shm_zone->shm.name.data,name->len) == 0) &&
                (data->shm_zone->shm.size != shm_size)) {
                shm_size = data->shm_zone->shm.size;
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "Cannot change memory area size without restart, ignoring change on zone: %V", name);
            }
        }
	}
	
	ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Using %udKiB of shared memory for http_queue_module on zone: %V", shm_size >> 10, name);
    mcf->shm_zone = ngx_shared_memory_add(cf, name, shm_size, &ngx_http_queue_module);

    if (mcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (mcf->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate zone \"%V\"", name);
        return NGX_CONF_ERROR;
    }

    mcf->shm_zone->init = ngx_http_queue_module_init_shm_zone;
    mcf->shm_zone->data = mcf;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_queue_module_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_queue_module_global_shm_data_t *global_shm_data = (ngx_http_queue_module_global_shm_data_t *) ngx_http_queue_module_global_shm_zone->data;
    ngx_http_queue_module_main_conf_t       *mcf = shm_zone->data;
    ngx_http_queue_module_shm_data_t        *d;

    mcf->shm_zone = shm_zone;
    mcf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (data) { 
        shm_zone->data = data;
        d = (ngx_http_queue_module_shm_data_t *) data;
        d->mcf = mcf;
        d->shm_zone = shm_zone;
        d->shpool = mcf->shpool;
        mcf->shm_data = data;
        ngx_queue_insert_tail(&global_shm_data->shm_datas_queue, &d->shm_datas_queue);
        return NGX_OK;
    }

    ngx_rbtree_node_t                   *sentinel;

    if ((d = (ngx_http_queue_module_shm_data_t *) ngx_slab_alloc(mcf->shpool, sizeof(*d))) == NULL) { //shm_data plus an array.
        return NGX_ERROR;
    }
    d->mcf = mcf;
    mcf->shm_data = d;
    shm_zone->data = d;

    d->stored_channels = 0;
    d->stored_messages = 0;
    d->shm_zone = shm_zone;
    d->shpool = mcf->shpool;

    // initialize rbtree
    if ((sentinel = ngx_slab_alloc(mcf->shpool, sizeof(*sentinel))) == NULL) {
        return NGX_ERROR;
    }
    ngx_rbtree_init(&d->tree, sentinel, ngx_http_queue_module_rbtree_insert);

    ngx_queue_init(&d->channels_queue);
  
    ngx_queue_insert_tail(&global_shm_data->shm_datas_queue, &d->shm_datas_queue);

    return NGX_OK;
}

ngx_int_t
ngx_http_queue_module_init_global_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t                            *shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ngx_http_queue_module_global_shm_data_t     *d;

    if (data) { /* zone already initialized */
        shm_zone->data = data;
        ngx_queue_init(&((ngx_http_queue_module_global_shm_data_t *) data)->shm_datas_queue);
        ngx_http_queue_module_global_shm_zone = shm_zone;
        return NGX_OK;
    }

    if ((d = (ngx_http_queue_module_global_shm_data_t *) ngx_slab_alloc(shpool, sizeof(*d))) == NULL) { //shm_data plus an array.
        return NGX_ERROR;
    }
    shm_zone->data = d;

    ngx_queue_init(&d->shm_datas_queue);

    ngx_http_queue_module_global_shm_zone = shm_zone;

    return NGX_OK;
}

static ngx_int_t
ngx_http_queue_module_preconfig(ngx_conf_t *cf)
{
    size_t size = ngx_align(2 * sizeof(ngx_http_queue_module_global_shm_data_t), ngx_pagesize);
    ngx_shm_zone_t     *shm_zone = ngx_shared_memory_add(cf, &ngx_http_queue_module_global_shm_name, size, &ngx_http_queue_module);

    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    shm_zone->init = ngx_http_queue_module_init_global_shm_zone;
    shm_zone->data = (void *) 1;

    return NGX_OK;
}

static char *
ngx_http_queue_module_init_main_conf(ngx_conf_t *cf, void *parent)
{
    ngx_http_queue_module_main_conf_t     *conf = parent;

    if (!conf->enabled) {
        return NGX_CONF_OK;
    }
	
	if ((conf->max_number_of_channels != NGX_CONF_UNSET_UINT) && (conf->max_number_of_channels == 0)) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "queue module: queue_module_max_number_of_channels cannot be zero.");
        return NGX_CONF_ERROR;
    }
		
    if ((conf->max_messages_stored_per_channel != NGX_CONF_UNSET_UINT) && (conf->max_messages_stored_per_channel == 0)) {
       ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "queue module: queue_module_max_messages_stored_per_channel cannot be zero.");
       return NGX_CONF_ERROR;
  	}

    return NGX_CONF_OK;
}
