#ifndef NGX_HTTP_QUEUE_MODULE_H_
#define NGX_HTTP_QUEUE_MODULE_H_
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

typedef struct ngx_http_queue_module_shm_data_s ngx_http_queue_module_shm_data_t;
typedef struct ngx_http_queue_module_global_shm_data_s ngx_http_queue_module_global_shm_data_t;

static ngx_str_t    ngx_http_queue_module_shm_name = ngx_string("queue_module");
static ngx_str_t    ngx_http_queue_module_global_shm_name = ngx_string("queue_module_global");

static const ngx_str_t  NGX_HTTP_QUEUE_MODULE_HEADER_EVENT_ID = ngx_string("Event-Id");
static const ngx_str_t  NGX_HTTP_QUEUE_MODULE_HEADER_EVENT_TYPE = ngx_string("Event-Type");

#define NGX_HTTP_QUEUE_MODULE_NUMBER_OF_CHANNELS_EXCEEDED    (void *) -2
#define NGX_HTTP_QUEUE_MODULE_NUMBER_OF_MESSAGES_EXCEEDED    (void *) -3

ngx_int_t           ngx_http_queue_module_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t			ngx_http_queue_module_init_global_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

typedef struct {
    ngx_flag_t                      enabled;
    ngx_uint_t                      max_number_of_channels;
	ngx_uint_t                      max_messages_stored_per_channel;
    ngx_shm_zone_t                 *shm_zone;
    ngx_slab_pool_t                *shpool;
    ngx_http_queue_module_shm_data_t *shm_data;
} ngx_http_queue_module_main_conf_t;

typedef struct {
    ngx_http_complex_value_t       *channel_id;
	ngx_http_complex_value_t 	   *channel_key;
    ngx_flag_t                      stored_messages;
} ngx_http_queue_module_loc_conf_t;

typedef struct {
    ngx_rbtree_node_t                   node; // this MUST be first
 	ngx_rbtree_t                        tree;
    ngx_queue_t                         queue;
    ngx_queue_t                        *queue_sentinel;
    ngx_str_t                           id;
    ngx_uint_t                          stored_messages;
    ngx_queue_t                         leafs_queue;
    time_t                              expires;
} ngx_http_queue_module_channel_t;

typedef struct {
    ngx_rbtree_node_t                   node; // this MUST be first
    ngx_str_t                          	key;
    ngx_uint_t                          stored_flag;
	ngx_queue_t							queue;
	ngx_queue_t                        *queue_sentinel;
    ngx_queue_t                         message_pointer;
    time_t                              expires;
} ngx_http_queue_module_leaf_t;

typedef struct {
    ngx_queue_t                         queue;
	ngx_str_t							id;
    ngx_uint_t                          stored_messages;
} ngx_http_queue_module_channel_info_t;

typedef struct {
    ngx_queue_t                     queue; // this MUST be first
    time_t                          expires;
    time_t                          time;
    ngx_int_t                       id;
    ngx_str_t                       raw;
    ngx_int_t                       tag;
    ngx_str_t                      *event_id;
    ngx_str_t                      *event_type;
} ngx_http_queue_module_msg_t;

typedef struct {
	ngx_chain_t                        *free;
} ngx_http_queue_module_ctx_t;

typedef struct {
    ngx_queue_t                         messages_queue;
    pid_t                               pid;
	time_t                              startup;
} ngx_http_queue_module_worker_data_t;

typedef struct {
    char                 *subtype;
    size_t                len;
    ngx_str_t            *content_type;
    ngx_str_t            *format_item;
    ngx_str_t            *format_group_head;
    ngx_str_t            *format_group_item;
    ngx_str_t            *format_group_last_item;
    ngx_str_t            *format_group_tail;
} ngx_http_queue_module_content_subtype_t;

struct ngx_http_queue_module_global_shm_data_s {
	ngx_http_queue_module_worker_data_t      ipc[NGX_MAX_PROCESSES];
    time_t                                  startup;
    ngx_queue_t                             shm_datas_queue;
};

struct ngx_http_queue_module_shm_data_s {
    ngx_rbtree_t                            tree;
    ngx_uint_t                              stored_messages; 
	ngx_uint_t 								stored_channels;
    ngx_queue_t                             channels_queue;
    ngx_queue_t                             shm_datas_queue;
    ngx_http_queue_module_main_conf_t       *mcf;
    ngx_shm_zone_t                          *shm_zone;
    ngx_slab_pool_t                         *shpool;
};

ngx_shm_zone_t     *ngx_http_queue_module_global_shm_zone = NULL;

static void *       ngx_http_queue_module_create_main_conf(ngx_conf_t *cf);

static ngx_int_t	ngx_http_queue_module_preconfig(ngx_conf_t *cf);

static char *	ngx_http_queue_module_init_main_conf(ngx_conf_t *cf, void *parent);

#endif
