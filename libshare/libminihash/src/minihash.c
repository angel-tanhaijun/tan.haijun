/*************************************************************************
	> File Name: minihash.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Thu 24 Jun 2021 07:05:20 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>

#include "minihash.h"



uint32_t RSHash(uint8_t* str, uint32_t len)      
{                                                     
	uint32_t b    = 378551;                        
	uint32_t a    = 63689;                         
	uint32_t hash = 0;                             
	uint32_t i    = 0;                             

	for(i = 0; i < len; str++, i++)                    
	{                                                  
		hash = hash * a + (*str);                       
		a    = a * b;                                   
	}                                                  

	return hash;                                       
}                                                     
/* End Of RS Hash Function */                         

uint32_t JSHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = 1315423911;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash ^= ((hash << 5) + (*str) + (hash >> 2));
   }
 
   return hash;
}
/* End Of JS Hash Function */
 
 
uint32_t PJWHash(uint8_t* str, uint32_t len)
{
   const uint32_t BitsInUnsignedInt = (uint32_t)(sizeof(uint32_t) * 8);
   const uint32_t ThreeQuarters     = (uint32_t)((BitsInUnsignedInt  * 3) / 4);
   const uint32_t OneEighth         = (uint32_t)(BitsInUnsignedInt / 8);
   const uint32_t HighBits          = (uint32_t)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
   uint32_t hash              = 0;
   uint32_t test              = 0;
   uint32_t i                 = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << OneEighth) + (*str);
 
      if((test = hash & HighBits)  != 0)
      {
         hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits));
      }
   }
 
   return hash;
}
/* End Of  P. J. Weinberger Hash Function */
 
 
uint32_t ELFHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = 0;
   uint32_t x    = 0;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << 4) + (*str);
      if((x = hash & 0xF0000000L) != 0)
      {
         hash ^= (x >> 24);
      }
      hash &= ~x;
   }
 
   return hash;
}
/* End Of ELF Hash Function */
 
 
uint32_t BKDRHash(uint8_t* str, uint32_t len)
{
   uint32_t seed = 131; /* 31 131 1313 13131 131313 etc.. */
   uint32_t hash = 0;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash = (hash * seed) + (*str);
   }
 
   return hash;
}
/* End Of BKDR Hash Function */
 
 
uint32_t SDBMHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = 0;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash = (*str) + (hash << 6) + (hash << 16) - hash;
   }
 
   return hash;
}
/* End Of SDBM Hash Function */
 
 
uint32_t DJBHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = 5381;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) + hash) + (*str);
   }
 
   return hash;
}
/* End Of DJB Hash Function */
 
 
uint32_t DEKHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = len;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
   }
   return hash;
}
/* End Of DEK Hash Function */
 
 
uint32_t BPHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = 0;
   uint32_t i    = 0;
   for(i = 0; i < len; str++, i++)
   {
      hash = hash << 7 ^ (*str);
   }
 
   return hash;
}
/* End Of BP Hash Function */
 
 
uint32_t FNVHash(uint8_t* str, uint32_t len)
{
   const uint32_t fnv_prime = 0x811C9DC5;
   uint32_t hash      = 0;
   uint32_t i         = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash *= fnv_prime;
      hash ^= (*str);
   }
 
   return hash;
}
/* End Of FNV Hash Function */
 

uint32_t APHash(uint8_t* str, uint32_t len)
{
   uint32_t hash = 0xAAAAAAAA;
   uint32_t i    = 0;
 
   for(i = 0; i < len; str++, i++)
   {
      hash ^= ((i & 1) == 0) ? (  (hash <<  7) ^ (*str) * (hash >> 3)) :
                               (~((hash << 11) + ((*str) ^ (hash >> 5))));
   }
 
   return hash;
}
/* End Of AP Hash Function */



#define LEFTSHIFT(x,c) (((x) << (c)) | ((x) >> (32-(c))))

static const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// per-round shift amounts
static const uint32_t r[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static void to_bytes(uint32_t val, uint8_t *bytes){
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

static uint32_t to_int32(const uint8_t *bytes){
    return (uint32_t)bytes[0] 
    | ((uint32_t)bytes[1] << 8) 
    | ((uint32_t)bytes[2] << 16) 
    | ((uint32_t)bytes[3] << 24);
}


static void minihash_md5(const uint8_t *initial_msg, size_t initial_len, uint8_t* digest){
    size_t new_len, offset;
    uint32_t words[16];
    uint8_t *newmsg = NULL;
    uint32_t h0, h1, h2, h3, a, b, c, d, f, g, temp;
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
    // Pre-processing
    // calculate new length (not included last 8bytes)
    for (new_len = initial_len+1; new_len % (512/8) != 448/8; new_len++);
    newmsg = (uint8_t*)malloc(new_len+8); // 8 bytes for length recording
    memcpy(newmsg, initial_msg, initial_len);
    newmsg[initial_len]=0x80; // padding "1" first, then all "0"
    for (offset = initial_len+1; offset < new_len; offset++)
        newmsg[offset] = 0x00;
    // append the len in bits at the end of buffer ??? why << 3
    to_bytes(initial_len << 3, newmsg + new_len);
    to_bytes(initial_len >> 29, newmsg + new_len + 4);

    // process the message per 512-bits
    for (offset = 0; offset < new_len; offset += (512/8)){
        // break 512 bits into 16 words(32-bit)
        for (uint32_t i = 0; i < 16; i ++)
            words[i] = to_int32(newmsg + offset + i*4);
        a = h0; b = h1; c = h2; d = h3;
        for (uint32_t i = 0; i < 64; i ++){
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g =  i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*(i-16) + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*(i-32) + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7*(i-48)) % 16;
            }
            temp = d;
            d = c;
            c = b;
            b = b + LEFTSHIFT((a+f+k[i]+words[g]), r[i]);
            a = temp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
    free(newmsg);
    to_bytes(h0, digest);
    to_bytes(h1, digest+4);
    to_bytes(h2, digest+8);
    to_bytes(h3, digest+12);
	return;
}

#pragma pack (1)  




typedef struct minihash_node{
	uint64_t insert_time;
	uint64_t updata_time;
	uint8_t  node_opy;
	uint8_t  *key;
	uint8_t  *value;
	struct   minihash_node *next;
}minihash_node_t;

typedef struct{
	uint32_t bucketn;
	uint32_t noden;
	uint32_t key_len;
	uint32_t value_len;
	uint32_t et_mode;
	uint32_t *node_count;
	minihash_node_t **bucket;
}minihash_t;
         
#pragma pack (0)  

#define MINIHASH_NODE_OPY    0xFF
#define MINIHASH_NODE_NOPY   0


static uint32_t minihash_find_bucket(minihash_t *minihash, uint8_t *key, uint32_t key_len)
{
	uint8_t md5[16] = {0};	
	minihash_md5(key, key_len, md5);	
	return (BKDRHash(md5, sizeof(md5))%minihash->bucketn);   	
}

static uint64_t minihash_get_usec()
{
	struct timeval now_time;
	gettimeofday(&now_time, NULL);
	return (1000000*now_time.tv_sec + now_time.tv_usec);
}


void *minihash_create(uint32_t bucket, uint32_t node, uint32_t key_len, uint32_t value_len, uint32_t et_mode)
{
	if(bucket <= 0 || node <= 0 || key_len <= 0 || value_len <= 0 )
	{
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);
		return NULL;
	}
	if(et_mode >= max_expire)
	{
		printf("[%s-%s-%d] et_mode error\n", __FILE__, __func__, __LINE__);
		return NULL;
	}
	minihash_t *minihash = (minihash_t *)malloc(sizeof(minihash_t));	
	assert(minihash != NULL);
	
	minihash->bucketn    = bucket;
	minihash->noden      = node;
	minihash->key_len    = key_len;
	minihash->value_len  = value_len;
	minihash->et_mode    = et_mode;
	minihash->bucket     = malloc(sizeof(minihash_node_t *)*bucket);
	assert(minihash->bucket != NULL);
	minihash->node_count = malloc(sizeof(uint32_t *)*bucket);
	assert(minihash->node_count != NULL);
	return (void *)minihash;
}
int minihash_build_table(void *minihash)
{
	if(minihash == NULL)
	{
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);
		return -1;                                                          
	}
	int i = 0;
	minihash_t *pminihash = (minihash_t *)minihash;

	for(i = 0; i < pminihash->bucketn; i++)
	{
		pminihash->bucket[i]         = NULL;
		pminihash->node_count[i]     = malloc(sizeof(uint32_t));
		assert(pminihash->node_count[i] != NULL);
		pminihash->node_count[i]     = 0;
	}
	return 0;
}

void *minihash_find_node(void *minihash, uint8_t *key, uint32_t key_len)
{
	if(minihash == NULL || key == NULL || key_len <= 0)
	{
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);
		return -1;                                                      
	}
	minihash_t *pminihash = (minihash_t *)minihash;
	if(key_len != pminihash->key_len)
	{
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__); 
		return -1;                                                             
	}
	
	uint32_t bucket = minihash_find_bucket(pminihash, key, key_len);

	minihash_node_t *node = pminihash->bucket[bucket]; 
	minihash_node_t *last_node = node;                 

	while(node != NULL)                           
	{                                                  
		if(memcmp(node->key, key, key_len) == 0)       
			goto leave;
		last_node = node;                              
		node      = last_node->next;                   
	}                                                  
	return NULL;
leave:
	node->updata_time = minihash_get_usec();
	return node->value;                     
}


int minihash_add_node(void *minihash, uint8_t *key, uint32_t key_len, uint8_t *value, uint32_t value_len)
{
	if(minihash == NULL || key == NULL || key_len <= 0 || value == NULL || value_len <= NULL)
	{
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);
		return -1;                                                      
	}
	minihash_t *pminihash = (minihash_t *)minihash;
	if(key_len != pminihash->key_len || value_len != pminihash->value_len)
	{
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__); 
		return -1;                                                             
	}
	if(NULL != minihash_find_node(minihash, key, key_len))
	{
		printf("[%s-%s-%d] node add fail\n", __FILE__, __func__, __LINE__);  
		return -1;                                                              
	}
	
	uint32_t bucket = minihash_find_bucket(pminihash, key, key_len);
	if(pminihash->node_count[bucket] > pminihash->noden)
	{
		printf("[%s-%s-%d] node full\n", __FILE__, __func__, __LINE__);
		return -2;                                                         
	}
	
	minihash_node_t *node = pminihash->bucket[bucket];
	minihash_node_t *last_node = node;
	minihash_node_t *add_node  = NULL;
	while(node != NULL)
	{
		last_node = node;
		node      = last_node->next; 
	}
	add_node   = (minihash_node_t *)malloc(sizeof(minihash_node_t));
	assert(add_node != NULL);
	if(last_node == NULL)
		pminihash->bucket[bucket] = add_node;	
	else
		last_node->next = add_node; 

	add_node->node_opy     = MINIHASH_NODE_OPY;
	add_node->insert_time  = minihash_get_usec();
	add_node->updata_time  = minihash_get_usec();
	add_node->key          = malloc(key_len);
	assert(add_node->key   != NULL);
	add_node->value        = malloc(value_len);
	assert(add_node->value != NULL);
	memcpy(add_node->key, key, key_len);
	memcpy(add_node->value, value, value_len);
	add_node->next         = NULL;
	pminihash->node_count[bucket]++;
	return 0;
}

int minihash_minus_node(void *minihash, uint8_t *key, uint32_t key_len)
{
	if(minihash == NULL || key == NULL || key_len <= 0)                                    
	{                                                                                      
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);             
		return -1;                                                                         
	}                                                                                      
	minihash_t *pminihash = (minihash_t *)minihash;                                        
	if(key_len != pminihash->key_len)                                                      
	{                                                                                      
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);             
		return -2;                                                                         
	} 
	uint32_t bucket = minihash_find_bucket(pminihash, key, key_len);
	minihash_node_t *node = pminihash->bucket[bucket];                
	minihash_node_t *last_node = node;                                

	while(pminihash->bucket[bucket] != NULL && memcmp(pminihash->bucket[bucket]->key, key, key_len) == 0)                                          
	{                                                                 
		pminihash->node_count[bucket]--;

		free(node->value);
		free(node->key); 
		pminihash->bucket[bucket] = pminihash->bucket[bucket]->next;
		free(node);
		node = pminihash->bucket[bucket];
	}
	if(pminihash->bucket[bucket] == NULL)
		return 0;
	node      = pminihash->bucket[bucket]->next;
	last_node = pminihash->bucket[bucket];
	while(node != NULL)
	{
		if(memcmp(node->key, key, key_len) == 0)
		{
			pminihash->node_count[bucket]--;
			last_node->next = node->next;
			free(node->value);
			free(node->key); 
			free(node);
			node = last_node->next;
		}
		else
		{
			last_node = node;
			node      = node->next;
		}
	}
	return 0;                                                      
}

int minihash_destroy(void *minihash)
{
	if(minihash == NULL)                         
	{                                                                           
		printf("[%s-%s-%d] parameters error\n", __FILE__, __func__, __LINE__);  
		return -1;                                                              
	}    
	int i = 0;
	minihash_t *pminihash = (minihash_t *)minihash;
	
	for(i = 0; i < pminihash->bucketn; i++)
	{
		minihash_node_t *node = pminihash->bucket[i]; 
		minihash_node_t *last_node = NULL;	
		while(node != NULL)
		{
			free(node->value);            
			free(node->key);
			last_node = node;
			node      = node->next;     
			free(last_node);                   
		}
	}
	return 0;
}

