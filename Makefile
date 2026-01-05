SUBDIRS = kernel user

.PHONY: all clean install uninstall $(SUBDIRS)

all: $(SUBDIRS)

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

install:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir install; \
	done

uninstall:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir uninstall; \
	done

$(SUBDIRS):
	$(MAKE) -C $@
