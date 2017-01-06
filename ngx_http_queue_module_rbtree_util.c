#include "ngx_http_queue_module_rbtree_util.h"

static ngx_http_queue_module_channel_t *
ngx_http_queue_module_find_channel_on_tree(ngx_str_t *id, ngx_log_t *log, ngx_rbtree_t *tree)
{
    uint32_t                            hash;
    ngx_rbtree_node_t                  *node, *sentinel;
    ngx_int_t                           rc;
    ngx_http_queue_module_channel_t      *channel = NULL;

    hash = ngx_crc32_short(id->data, id->len);

    node = tree->root;
    sentinel = tree->sentinel;

    while ((node != NULL) && (node != sentinel)) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        channel = (ngx_http_queue_module_channel_t *) node;

        rc = ngx_memn2cmp(id->data, channel->id.data, id->len, channel->id.len);
        if (rc == 0) {
            return channel;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static ngx_http_queue_module_leaf_t *
ngx_http_queue_module_find_leaf_on_tree(ngx_str_t *key, ngx_log_t *log, ngx_rbtree_t *tree)
{
    uint32_t                            hash;
    ngx_rbtree_node_t                  *node, *sentinel;
    ngx_int_t                           rc;
    ngx_http_queue_module_leaf_t       *leaf = NULL;

    hash = ngx_crc32_short(key->data, key->len);

    node = tree->root;
    sentinel = tree->sentinel;

    while ((node != NULL) && (node != sentinel)) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        leaf = (ngx_http_queue_module_leaf_t *) node;

        rc = ngx_memn2cmp(key->data, leaf->key.data, key->len, leaf->key.len);
        if (rc == 0) {
            return leaf;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static ngx_int_t
ngx_http_queue_module_initialize_channel(ngx_http_queue_module_main_conf_t *mcf, ngx_http_queue_module_channel_t *channel)
{
    ngx_http_queue_module_shm_data_t    *data = mcf->shm_data;

    channel->stored_messages = 0;

	ngx_rbtree_node_t                   *sentinel;
	
	if ((sentinel = ngx_slab_alloc_locked(mcf->shpool, sizeof(*sentinel))) == NULL) {
        return NGX_ERROR;
    }
    ngx_rbtree_init(&channel->tree, sentinel, ngx_http_queue_module_rbtree_insert);
    
    ngx_queue_init(&channel->leafs_queue);
    
    channel->node.key = ngx_crc32_short(channel->id.data, channel->id.len);
    ngx_rbtree_insert(&data->tree, &channel->node);
    ngx_queue_insert_tail(&data->channels_queue, &channel->queue);
    channel->queue_sentinel = &data->channels_queue;
	return NGX_OK;
}

static ngx_int_t
ngx_http_queue_module_initialize_leaf(ngx_http_queue_module_main_conf_t *mcf, ngx_http_queue_module_channel_t *channel, ngx_http_queue_module_leaf_t *leaf)
{
    leaf->stored_flag = 0;

    ngx_queue_init(&leaf->message_pointer);

    leaf->node.key = ngx_crc32_short(leaf->key.data, leaf->key.len);
    ngx_rbtree_insert(&channel->tree, &leaf->node);
    ngx_queue_insert_tail(&channel->leafs_queue, &leaf->queue);
	leaf->queue_sentinel = &channel->leafs_queue;
	return NGX_OK;
}

static ngx_http_queue_module_channel_t *
ngx_http_queue_module_find_channel(ngx_str_t *id, ngx_log_t *log, ngx_http_queue_module_main_conf_t *mcf)
{
    ngx_http_queue_module_shm_data_t        *data = mcf->shm_data;
    ngx_http_queue_module_channel_t     	*channel = NULL;

    if (id == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "push stream module: tried to find a channel with a null id");
        return NULL;
    }

    channel = ngx_http_queue_module_find_channel_on_tree(id, log, &data->tree);
    if (channel == NULL) {
        return NULL;
    }

    return channel;
}

static ngx_http_queue_module_leaf_t *
ngx_http_queue_module_find_leaf(ngx_str_t *id, ngx_str_t *key, ngx_log_t *log, ngx_http_queue_module_main_conf_t *mcf)
{
    ngx_http_queue_module_leaf_t     	  *leaf = NULL;
	ngx_http_queue_module_channel_t       *channel =  ngx_http_queue_module_find_channel(id, log, mcf);

    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "push stream module: tried to find a channel with a null id");
        return NULL;
    }

    leaf = ngx_http_queue_module_find_leaf_on_tree(key, log, &channel->tree);
    if (leaf == NULL) {
        return NULL;
    }

    return leaf;
}

static ngx_http_queue_module_main_conf_t *
ngx_http_queue_module_get_channel(ngx_str_t *id, ngx_log_t *log, ngx_http_queue_module_loc_conf_t *cf, ngx_http_queue_module_main_conf_t *mcf)
{
    ngx_http_queue_module_shm_data_t       *data = mcf->shm_data;
    ngx_http_queue_module_channel_t        *channel;
    ngx_slab_pool_t                        *shpool = mcf->shpool;

    channel = ngx_http_queue_module_find_channel(id, log, mcf);
    if (channel != NULL) { // we found our channel
        return mcf;
    }
	ngx_shmtx_lock(&shpool->mutex);
	
	channel = ngx_http_queue_module_find_channel(id, log, mcf);
    if (channel != NULL) { // we found our channel
        ngx_shmtx_unlock(&shpool->mutex);
        return mcf;
    }
    
    if ((mcf->max_number_of_channels != NGX_CONF_UNSET_UINT) && (mcf->max_number_of_channels == data->stored_channels)) {
        ngx_shmtx_unlock(&shpool->mutex);
       	return NGX_HTTP_QUEUE_MODULE_NUMBER_OF_CHANNELS_EXCEEDED;
    }

    if ((channel = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_queue_module_channel_t))) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return mcf;
    }

    if ((channel->id.data = ngx_slab_alloc_locked(shpool, id->len + 1)) == NULL) {
        ngx_slab_free_locked(shpool, channel);
        ngx_shmtx_unlock(&shpool->mutex);
        return mcf;
    }

    channel->id.len = id->len;
    ngx_memcpy(channel->id.data, id->data, channel->id.len);
    channel->id.data[channel->id.len] = '\0';
	data->stored_channels++;	
    ngx_http_queue_module_initialize_channel(mcf, channel);
    ngx_shmtx_unlock(&shpool->mutex);

    return  mcf;
}


static ngx_http_queue_module_main_conf_t *
ngx_http_queue_module_get_leaf(ngx_str_t *id, ngx_str_t *key, ngx_log_t *log, ngx_http_queue_module_loc_conf_t *cf, ngx_http_queue_module_main_conf_t *mcf)
{
    ngx_http_queue_module_channel_t          *channel = ngx_http_queue_module_find_channel(id, log, mcf);
    ngx_http_queue_module_leaf_t           *leaf;
    ngx_slab_pool_t                        *shpool = mcf->shpool;

    leaf = ngx_http_queue_module_find_leaf(id, key, log, mcf);
    if (leaf != NULL) { // we found our leaf
        return mcf;
    }
    ngx_shmtx_lock(&shpool->mutex);

    leaf = ngx_http_queue_module_find_leaf(id, key, log, mcf);
    if (leaf != NULL) { // we found our leaf
        ngx_shmtx_unlock(&shpool->mutex);
        return mcf;
    }

    if ((mcf->max_messages_stored_per_channel != NGX_CONF_UNSET_UINT) && (mcf->max_messages_stored_per_channel == channel->stored_messages)) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_QUEUE_MODULE_NUMBER_OF_MESSAGES_EXCEEDED;
    }

    if ((leaf = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_queue_module_leaf_t))) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return mcf;
    }

    if ((leaf->key.data = ngx_slab_alloc_locked(shpool, key->len + 1)) == NULL) {
        ngx_slab_free_locked(shpool,leaf);
        ngx_shmtx_unlock(&shpool->mutex);
        return mcf;
    }

    leaf->key.len = key->len;
    ngx_memcpy(leaf->key.data, key->data, leaf->key.len);
    leaf->key.data[leaf->key.len] = '\0';
    ngx_http_queue_module_initialize_leaf(mcf, channel, leaf);
	mcf->shm_data->stored_messages++;
    ngx_shmtx_unlock(&shpool->mutex);
    return  mcf;
}

static void
ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, int (*compare) (const ngx_rbtree_node_t *left, const ngx_rbtree_node_t *right))
{
    ngx_rbtree_node_t       **p;

    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else { /* node->key == temp->key */
            p = (compare(node, temp) < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static void
ngx_http_queue_module_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_generic_insert(temp, node, sentinel, ngx_http_queue_module_compare_rbtree_node);
}

static int
ngx_http_queue_module_compare_rbtree_node(const ngx_rbtree_node_t *v_left, const ngx_rbtree_node_t *v_right)
{
    //ngx_http_queue_module_channel_t *left = (ngx_http_queue_module_channel_t *) v_left, *right = (ngx_http_queue_module_channel_t *) v_right;

    //return ngx_memn2cmp(left->id.data, right->id.data, left->id.len, right->id.len);
	return 0;
}
