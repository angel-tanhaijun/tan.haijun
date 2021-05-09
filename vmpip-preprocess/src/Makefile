CC = gcc
#CFLAGS = -g -Wall -rdynamic -w  -lsndfile -ltiff
ifeq ($(debug), 1)
	CFLAGS += -g -fgnu89-inline -Wno-misleading-indentation
else ifeq ($(release), 1)
	CFLAGS += -O2 -fno-strict-aliasing -fgnu89-inline -Wno-misleading-indentation
else ifeq ($(error-check), 1)
	CFLAGS += -ggdb -fsanitize=address -fgnu89-inline -Wno-misleading-indentation
else
	CFLAGS += -g -fgnu89-inline -Wno-misleading-indentation 
#-lsndfile -ltiff
endif
#传真数据解析编译需要链接 -lsndfile -ltiff
#CFLAGS = -g -Wall -O2 -fno-strict-aliasing -rdynamic
#CFLAGS       = -W -Wall -Wno-unused-parameter -g  -rdynamic -fstack-protector-all
LIB = -L    ../libs \
	  -L    ../../firebird/libs \
	  -L    ../../libshares/libs \
	  -L    ../../ncalibs/libs \
	        -lm -lvshell -lpthread -lutils -ldl -lxml2 -lxmlcfg -lrbque -ltcpsend -lzlog -lev -lminihash.0.9 -llla \
		   	-lpcap -lfirebird_l2parser -lfirebird_utils -ltcpclient -ludpserver	
	                        
INCLUDE = 	-I ../include  \
			-I ../../firebird/include  \
			-I ../../libshares/include  \
			-I ../../ncalibs/include
			
DST = front_midware

GIT_ENV_VERSION=$(shell [[ -x ./git-env.sh ]] && ./git-env.sh)
MODIFIED_D := $(shell date +%F)
MODIFIED_T := $(shell date +%T)
MODIFIED    = "\"$(GIT_ENV_VERSION) $(MODIFIED_D) $(MODIFIED_T)"\"
CFLAGS      += -DVERSION=$(MODIFIED)

SRC = $(wildcard *.c) $(wildcard *.cpp)
OBJ = $(patsubst %.c,%.o,$(SRC))

%.o:%.c
	$(ECHO) $(CC)  -c $(CFLAGS) $(INCLUDE) $< -o $@

$(DST):$(OBJ)
	$(CC) -o $(DST) $(OBJ) $(CFLAGS) $(INCLUDE) $(LIB)
	$(ECHO) rm -f *.o
	mv $(DST) ../
clean:
	$(ECHO) rm -f *.o
	rm -f ../$(DST)
