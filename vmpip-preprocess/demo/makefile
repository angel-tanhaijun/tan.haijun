ECHO = @
CC ?= gcc -Wl,--export-dynamic -ldl -D__int64="long long"
L7P ?= 
SP ?= 

PLATFORM_PATH=../../firebird
LIBSHARE = ../../libshares


GIT_ENV_VERSION=$(shell [[ -x ./git-env.sh ]] && ./git-env.sh)
MODIFIED_D := $(shell date +%F)
MODIFIED_T := $(shell date +%T)
MODIFIED    = "\"$(GIT_ENV_VERSION) $(MODIFIED_D) $(MODIFIED_T)"\"

CFLAGS      ?= -g  
CFLAGS      += -DVERSION=$(MODIFIED)

#-lH235-SECURITY-MESSAGES -lfirebird_h225 -lh225_proc -lfirebird_h245 -lh245_proc
#-lfirebird_h225 -lh225_proc -lfirebird_h245 -lh245_proc -lH235-SECURITY-MESSAGES 

#
##PROTO_LIBS = -lfirebird_dcerpc -ldcerpc_proc  -lsmtp -lsmtp_proc -lpop3  -limap_proc -limap  -lpop3_proc
LDFLAGS      +=  -L ../libs        \
				-L $(PLATFORM_PATH)/libs		\
				-L $(LIBSHARE)/libs		    \
				-lfirebird_cache -lfirebird_mem_pool -lfirebird_utils \
				-lfirebird_flowstat -lpcap -lfirebird_l2parser -lrbque -ltcpsend -lev \
				-loffline_proc -llla -lminihash.0.9\
				-lxmlcfg -lvshell -lxml2 -lpthread  -liconv  -lzlog -lz 

INCLUDE 	+=  -I ../include \
				-I $(PLATFORM_PATH)/include/   \
				-I $(LIBSHARE)/include/  

PROGRAMNAME = start

SRC_C = $(wildcard *.c )
OBJ_C = $(patsubst %.c,%.o,$(SRC_C))

%.o:%.c 
	$(ECHO) $(CC) -c  $(INCLUDE) $(CFLAGS)  $< -o $@

all : $(PROGRAMNAME)
$(PROGRAMNAME) : $(OBJ_C)
	$(ECHO) $(CC)  $(OBJ_C)  -o $(PROGRAMNAME) $(INCLUDE)   $(CFLAGS) $(LDFLAGS)
	$(ECHO) rm *.o

clean:
	$(ECHO) $(RM) *.o *~ tags $(PROGRAMNAME)
