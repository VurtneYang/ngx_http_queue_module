#ifndef NGX_HTTP_QUEUE_MODULE_RBTREE_UTIL_H_
#define NGX_HTTP_QUEUE_MODULE_RBTREE_UTIL_H_
#include "ngx_http_queue_module.h"

static ngx_http_queue_module_main_conf_t *	ngx_http_queue_module_get_channel(ngx_str_t *id, ngx_log_t *log, ngx_http_queue_module_loc_conf_t *cf, ngx_http_queue_module_main_conf_t *mcf);
static ngx_http_queue_module_main_conf_t * 	ngx_http_queue_module_get_leaf(ngx_str_t *id, ngx_str_t *key, ngx_log_t *log, ngx_http_queue_module_loc_conf_t *cf, ngx_http_queue_module_main_conf_t *mcf);
static ngx_http_queue_module_channel_t * 		ngx_http_queue_module_find_channel(ngx_str_t *id, ngx_log_t *log, ngx_http_queue_module_main_conf_t *mcf);
static ngx_http_queue_module_leaf_t *    ngx_http_queue_module_find_leaf(ngx_str_t *id, ngx_str_t *key, ngx_log_t *log, ngx_http_queue_module_main_conf_t *mcf);

static void         ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, int (*compare) (const ngx_rbtree_node_t *left, const ngx_rbtree_node_t *right));
static void         ngx_http_queue_module_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static int          ngx_http_queue_module_compare_rbtree_node(const ngx_rbtree_node_t *v_left, const ngx_rbtree_node_t *v_right);

#endif
