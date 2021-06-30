/*************************************************************************
	> File Name: main.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Fri 25 Jun 2021 12:30:56 AM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "minihash.h"

#pragma pack (1)

typedef struct{
	uint32_t add_num;
	uint8_t  buff[125];
	uint32_t bufflen;
	uint8_t  *piont;
}add_value_t;


#pragma pack (0)


int main()
{
	
	void *hashhand = minihash_create(10000, 100, sizeof(uint32_t), sizeof(add_value_t), forbid_expire);
	if(hashhand == NULL)
		return 0;
	if(minihash_build_table(hashhand) != 0)
		return 0;
	
	int i = 0;
	for(i = 0; i < 100000; i++)
	{
		add_value_t add_value;
		memset(&add_value, 0, sizeof(add_value_t));
		add_value.add_num = i;
		snprintf(add_value.buff, sizeof(add_value.buff),"%d_test", i);
		add_value.bufflen = strlen(add_value.buff);
		add_value.piont = "192.168.0.1";
		minihash_add_node(hashhand, (uint8_t *)&i, sizeof(i), (uint8_t *)&add_value, sizeof(add_value_t));
	}
	for(i = 0; i < 100000; i++)
	{
		add_value_t *value = (add_value_t *)minihash_find_node(hashhand, (uint8_t *)&i, sizeof(i));
		if(value == NULL)
			continue;
		printf("add_num:%d, buff:%s, piont:%s\n", value->add_num, value->buff, value->piont);
	
		minihash_minus_node(hashhand, (uint8_t *)&i, sizeof(i));
	}

	i = 1;
	while(1)
	{
		add_value_t add_value;
		memset(&add_value, 0, sizeof(add_value_t));
		add_value.add_num = i;
		snprintf(add_value.buff, sizeof(add_value.buff),"%d_test", i);
		add_value.bufflen = strlen(add_value.buff);
		add_value.piont = "192.168.0.1";
		minihash_add_node(hashhand, (uint8_t *)&i, sizeof(i), (uint8_t *)&add_value, sizeof(add_value_t));
		minihash_minus_node(hashhand, (uint8_t *)&i, sizeof(i));
	}

	minihash_destroy(hashhand);
	return 0;
}
