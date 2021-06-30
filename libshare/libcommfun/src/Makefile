.PHONY : clean 

SLIB := libcommfun.a
DLIB := libcommfun.so

OBJH := $(wildcard *.h)
SRC  := $(wildcard *.c )
OBJ  := $(patsubst %.c,%.o,$(SRC))

CC = gcc
AR ?= ar

#CFLAGS ?= -g -Wall -fgnu89-inline -Wno-misleading-indentation
CFLAGS ?= -g -Wall -rdynamic -w  
#-lsndfile -ltiff

SFLAGS = -c
DFLAGS = -fpic -shared

PLATFORM_PATH = ../../
LIBSHARES = ../../

INCLUDE 	+=  -I $(PLATFORM_PATH)/include/   \
				-I $(LIBSHARES)/include  \

GIT_ENV_VERSION=$(shell chmod +x ./git-env.sh && ./git-env.sh)
MODIFIED_D := $(shell date +%F)
MODIFIED_T := $(shell date +%T)
MODIFIED    = "\"$(GIT_ENV_VERSION) $(MODIFIED_D) $(MODIFIED_T)"\"
CFLAGS      += -DVERSION=$(MODIFIED)

ifeq ($(debug), 1)
else ifeq ($(release), 1)
	CFLAGS += -O2 -fno-strict-aliasing
else ifeq ($(error-check), 1)
	CFLAGS += -ggdb -fsanitize=address
endif

all: $(SLIB) $(DLIB)

%.o : %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDE)

$(SLIB):$(OBJ)
	$(AR) -r $(SLIB) $(OBJ)

$(DLIB):$(SRC)
	$(CC) $(DFLAGS) $(INCLUDE) $(CFLAGS) -o $(DLIB) $(SRC)

install:
	cp -f $(DLIB) $(SLIB) ../libs/
	cp -f $(OBJH) ../include/

uninstall:
	rm -f ../libs/*
	rm -f ../include/*

clean:
	rm -f *.o
	rm -f *.a
	rm -f *.so

