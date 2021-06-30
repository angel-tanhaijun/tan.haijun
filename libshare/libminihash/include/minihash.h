/*************************************************************************
	> File Name: minihash.h
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Thu 24 Jun 2021 07:29:23 PM PDT
 ************************************************************************/

#ifndef _MINIHASH_H_
#define _MINIHASH_H_

#include <stdint.h>

#pragma pack (1)

enum{
	forbid_expire = 0,  
	overtime_expire,
	fifo_expire,
	max_expire,
};

#pragma pack (0)


void *minihash_create(uint32_t bucket, uint32_t node, uint32_t key_len, uint32_t value_len, uint32_t et_mode);

int minihash_build_table(void *minihash);

void *minihash_find_node(void *minihash, uint8_t *key, uint32_t key_len);

int minihash_add_node(void *minihash, uint8_t *key, uint32_t key_len, uint8_t *value, uint32_t value_len);

int minihash_minus_node(void *minihash, uint8_t *key, uint32_t key_len);

int minihash_destroy(void *minihash);


#endif
