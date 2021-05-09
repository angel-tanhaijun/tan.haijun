CC = gcc
AR = ar
CFLAGS = -g -Wall -fgnu89-inline -Wno-misleading-indentation
MAKE = make

GCCVERSION ?= $(shell gcc --version |grep ^gcc | sed 's/^[^0-9]*\([0-9.]*\) .*/\1/g')
#ifeq "$(GCCVERSION)" "7.3.0"
CFLAGS = -g -Wall -fgnu89-inline -Wno-misleading-indentation
#else
#CFLAGS = -g -Wall -fgnu89-inline 
#endif

SUBDIRS = dvb_dyn ndci_dyn  rdvb_dyn  rndci_dyn src 

rhel_dir = rhel7.0

ifeq ($(debug), 1)
	dst_dir = debug
else ifeq ($(release), 1)
	dst_dir = release
	CFLAGS += -O2 -fno-strict-aliasing
else ifeq ($(error-check), 1)
	dst_dir = error-check
	CFLAGS += -ggdb -fsanitize=address
else
	dst_dir = debug
endif

export CFLAGS
.PHONY: all
all:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir ; \
		ret=$$?;  \
		if [ $$ret -ne 0 ];then \
			exit $$ret; \
		fi \
	done

.PHONY: clean
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) clean -C $$dir ; \
	done

.PHONY: install
install:
	for dir in $(SUBDIRS); do \
		$(MAKE) install -C $$dir ; \
	done
    
.PHONY: uninstall
uninstall:
	for dir in $(SUBDIRS); do \
		$(MAKE) uninstall -C $$dir ;\
	done

.PHONY: dist
dist:
	for dir in $(SUBDIRS); do \
		cp -f $$dir/include/* ../ncalibs/include/ ; \
		cp -f $$dir/libs/*.so ../ncalibs/$(rhel_dir)/$(dst_dir)/libs/ ; \
	done
