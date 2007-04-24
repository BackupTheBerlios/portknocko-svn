#KERNEL_DIR=/usr/src/linux-$(shell uname -r)
KERNEL_DIR=/usr/src/kernels/2.6.18-1.2798.fc6-i686

TARGET=xt_pknock.o

obj-m:=$(TARGET)
xt_pknock-objs:=$(OBJS)
TARGETS := $(obj-m:.o=.ko)

DESTDIR_ROOT:=/lib/modules/$(shell uname -r)
DESTDIR:=$(DESTDIR_ROOT)/kernel/net/netfilter

all:		
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$$PWD modules

$(TARGETS): all

install: 	$(TARGETS)
		@echo "Instalando en $(DESTDIR) ..."
		@test -d $(DESTDIR) || mkdir $(DESTDIR)
		@set -x;install -d $(DESTDIR) && install -p -m 644 $(TARGETS) $(DESTDIR)
uninstall: 	
		cd $(DESTDIR);rm -fv $(TARGETS)

clean:		
		rm -f .*.cmd *.mod.c *.ko *.o *~ core $(TARGETS)
		rm -fr .tmp_versions
