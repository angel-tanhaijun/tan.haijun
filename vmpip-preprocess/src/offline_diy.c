/*************************************************************************
	> File Name: offline_diy.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月19日 星期五 09时25分04秒
 ************************************************************************/

#include "offline.h"
int offline_diy_load(offline_diy_helper_t *diy_helper, char *libname)
{
	printf("offline_diy_load load %s start [%s-%s-%d]\n", libname, __FILE__, __func__, __LINE__);
	void *dynUserPtr = NULL;
	if(libname == NULL || diy_helper == NULL)
	{
		printf("offline_diy_load error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);	
		exit(0);
	}
	dynUserPtr = dlopen(libname, RTLD_LAZY);          
	if(!dynUserPtr)                                       
	{                                                     
		fprintf(stderr, "load %s failed.\n", libname);
		diy_helper->canflag = 0;
		return -1;
	}                                                     
	diy_helper->diy_init = (offline_diy_init_helper *)dlsym(dynUserPtr, "offline_diy_init");
	if(!diy_helper->diy_init)
	{
		fprintf(stderr, "load %s with func [%s] failed.\n", libname, "offline_diy_init");                                       
		exit(0);                                    	
	}
	diy_helper->diy_gain = (offline_diy_gain_helper *)dlsym(dynUserPtr, "offline_diy_gain");
	if(!diy_helper->diy_gain)
	{
		fprintf(stderr, "load %s with func [%s] failed.\n", libname, "offline_diy_gain");                               
		exit(0);        
	}
	diy_helper->diy_register = (offline_diy_register_helper *)dlsym(dynUserPtr, "offline_diy_register");
	if(!diy_helper->diy_register)
	{
		fprintf(stderr, "load %s with func [%s] failed.\n", libname, "offline_diy_register");                               
		exit(0);        
	}
	printf("offline_diy_load load %s end [%s-%s-%d]\n", libname, __FILE__, __func__, __LINE__);
	diy_helper->canflag = 1;
	return 0;
}


