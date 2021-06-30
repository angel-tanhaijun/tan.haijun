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
	        -lpthread -lrtq -lm
	                        
INCLUDE = 	-I ../include
			
DST = demo

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
clean:
	$(ECHO) rm -f *.o
	rm -f $(DST)
