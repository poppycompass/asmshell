.DEFAULT_GOAL := build
ALL_TARGETS := asmshell
.PHONY: test deps ${ALL_TARGETS}

all: ${ALL_TARGETS}

clean:
	rm ${ALL_TARGETS}

build: all

# dependency targets
DEST = $(shell mkdir -p deps/build; cd deps && pwd)
FIXRPATH := touch
LIBEXT := so
OS := $(shell uname -s)
ARCH := $(shell uname -m)

ifeq "$(OS)" "Darwin"
	LIBEXT = dylib
	FIXRPATH = @install_name_tool \
		-add_rpath @executable_path/lib \
		-add_rpath @executable_path/deps/lib \
		-change libunicorn.dylib @rpath/libunicorn.dylib \
		-change libunicorn.1.dylib @rpath/libunicorn.1.dylib \
		-change libunicorn.2.dylib @rpath/libunicorn.2.dylib \
		-change libcapstone.dylib @rpath/libcapstone.dylib \
		-change libcapstone.3.dylib @rpath/libcapstone.3.dylib \
		-change libcapstone.4.dylib @rpath/libcapstone.4.dylib \
		-change libkeystone.dylib @rpath/libkeystone.dylib \
		-change libkeystone.0.dylib @rpath/libkeystone.0.dylib \
		-change libkeystone.1.dylib @rpath/libkeystone.1.dylib
endif

# figure out if we can download Go
GOVERSION=1.9
ifeq "$(ARCH)" "x86_64"
	ifeq "$(OS)" "Darwin"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).darwin-amd64.tar.gz"
	else ifeq "$(OS)" "Linux"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).linux-amd64.tar.gz"
	endif
endif
ifeq "$(ARCH)" "i686"
	ifeq "$(OS)" "Linux"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).linux-386.tar.gz"
	endif
endif
ifneq (,$(filter $(ARCH),armv6l armv7l armv8l))
	ifeq "$(OS)" "Linux"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).linux-armv6l.tar.gz"
	endif
endif

ifeq ($(GOURL),)
	GOMSG = "Go 1.6 or later is required. Visit https://golang.org/dl/ to download."
else
	GODIR = go-$(ARCH)-$(OS)
endif

deps/$(GODIR):
	echo $(GOMSG)
	[ -n $(GOURL) ] && \
	mkdir -p deps/build deps/gopath && \
	cd deps/build && \
	curl -o go-dist.tar.gz "$(GOURL)" && \
	cd .. && tar -xf build/go-dist.tar.gz && \
	mv go $(GODIR)

deps/lib/libunicorn.1.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/unicorn-engine/unicorn.git && git --git-dir unicorn fetch; \
	cd unicorn && git clean -fdx && git reset --hard origin/master && \
	make && make PREFIX=$(DEST) install

deps/lib/libcapstone.3.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/aquynh/capstone.git && git --git-dir capstone pull; \
	cd capstone && git clean -fdx && git reset --hard origin/master; \
	mkdir build && cd build && cmake -DCAPSTONE_BUILD_STATIC=OFF -DCMAKE_INSTALL_PREFIX=$(DEST) -DCMAKE_BUILD_TYPE=RELEASE .. && \
	make -j2 PREFIX=$(DEST) install

deps/lib/libkeystone.0.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/keystone-engine/keystone.git && git --git-dir keystone pull; \
	cd keystone; git clean -fdx && git reset --hard origin/master; mkdir build && cd build && \
	cmake -DCMAKE_INSTALL_PREFIX=$(DEST) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" .. && \
	make -j2 install

deps: deps/lib/libunicorn.1.$(LIBEXT) deps/lib/libcapstone.3.$(LIBEXT) deps/lib/libkeystone.0.$(LIBEXT) deps/$(GODIR)

# Go executable targets
.gopath:
	mkdir -p .gopath/src/github.com/poppycompass
	ln -s ../../../.. .gopath/src/github.com/poppycompass/asmshell

LD_LIBRARY_PATH=
DYLD_LIBRARY_PATH=
ifneq "$(OS)" "Darwin"
	LD_LIBRARY_PATH := "$(LD_LIBRARY_PATH):$(DEST)/lib"
else
	DYLD_LIBRARY_PATH := "$(DYLD_LIBRARY_PATH):$(DEST)/lib"
endif
GOBUILD := go build -i
PATHX := '$(DEST)/$(GODIR)/bin:$(PATH)'
export CGO_CFLAGS = -I$(DEST)/include
export CGO_LDFLAGS = -L$(DEST)/lib

ifneq ($(wildcard $(DEST)/$(GODIR)/.),)
	export GOROOT := $(DEST)/$(GODIR)
endif
ifneq ($(GOPATH),)
	export GOPATH := $(GOPATH):$(shell pwd)/.gopath
else
	export GOPATH := $(DEST)/gopath:$(shell pwd)/.gopath
endif
DEPS=$(shell env PATH=$(PATHX) GOROOT=$(GOROOT) GOPATH=$(GOPATH) go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | grep '\.' | sort -u)
PKGS=$(shell env PATH=$(PATHX) GOROOT=$(GOROOT) GOPATH=$(GOPATH) go list ./go/... | sort -u | rev | sed -e 's,og/.*$$,,' | rev | sed -e 's,^,github.com/poppycompass/asmshell/go,')

# ifeq "ls, https://www.ecoop.net/coop/translated/GNUMake3.77/make_7.jp.html
# TODO: more DRY
asmshell: .gopath
	@echo "go get -u github.com/fatih/color"
	@sh -c "PATH=$(PATHX) go get -u github.com/fatih/color"
	@echo "go get -u github.com/jessevdk/go-flags"
	@sh -c "PATH=$(PATHX) go get -u github.com/jessevdk/go-flags"
	@echo "go get -u github.com/abiosoft/ishell"
	@sh -c "PATH=$(PATHX) go get -u github.com/abiosoft/ishell"
	@echo "go get -u github.com/chzyer/readline"
	@sh -c "PATH=$(PATHX) go get -u github.com/chzyer/readline"
	@echo "go get -u github.com/gorilla/websocket"
	@sh -c "PATH=$(PATHX) go get -u github.com/gorilla/websocket"
	@echo "$(GOBUILD) -o asmshell ./go"
	@sh -c "PATH=$(PATHX) $(GOBUILD) -o asmshell ./go"
#	$(FIXRPATH) asmshell
