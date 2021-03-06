.DEFAULT_GOAL := build
ALL_TARGETS := go unicorn keystone capstone symlink deps asmshell
.PHONY: clean ${ALL_TARGETS}

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

go:
	echo $(GOMSG)
	-[ -n $(GOURL) -a ! -e deps/build/go-dist.tar.gz ] && \
	mkdir -p deps/build deps/gopath && \
	cd deps/build && \
	curl -o go-dist.tar.gz "$(GOURL)" && \
	cd .. && tar -xf build/go-dist.tar.gz && \
	mv go $(GODIR)

unicorn:
	-cd deps/build && [ ! -e unicorn ] && \
	git clone https://github.com/unicorn-engine/unicorn.git && git --git-dir unicorn fetch; \
	cd unicorn && git clean -fdx && git reset --hard origin/master && \
	make && make PREFIX=$(DEST) install

keystone:
	-cd deps/build && [ ! -e keystone ] && \
	git clone https://github.com/keystone-engine/keystone.git && git --git-dir keystone pull; \
	cd keystone; git clean -fdx && git reset --hard origin/master; mkdir build && cd build && \
	cmake -DCMAKE_INSTALL_PREFIX=$(DEST) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" .. && \
	make -j2 install

capstone:
	-cd deps/build && [ ! -e capstone ] && \
	git clone https://github.com/aquynh/capstone && \
	cd capstone && git checkout 3.0.5 && mkdir build && cd build && \
	cmake -DCMAKE_INSTALL_PREFIX=$(DEST) .. && \
	make && make install

symlink:
	mkdir -p deps/gopath/src/github.com/poppycompass
	-ln -s ../../../../../ deps/gopath/src/github.com/poppycompass/asmshell

LD_LIBRARY_PATH=
DYLD_LIBRARY_PATH=
C_INCLUDE_PATH=
C_PLUS_INCLUDE_PATH=
ifneq "$(OS)" "Darwin"
	export DYLD_LIBRARY_PATH := "$(DEST)/lib:$(DEST)/lib64"
else
	export LD_LIBRARY_PATH := "$(DEST)/lib:$(DEST)/lib64"
endif
GOBUILD := go build -i
PATHX := '$(DEST)/$(GODIR)/bin:$(PATH)'
export CGO_CFLAGS = -I$(DEST)/include
export CGO_LDFLAGS = -L$(DEST)/lib -L$(DEST)/lib64
export C_INCLUDE_PATH := "$(DEST)/include"
export CPLUS_INCLUDE_PATH := "$(DEST)/include"

ifneq ($(wildcard $(DEST)/$(GODIR)/.),)
	export GOROOT := $(DEST)/$(GODIR)
endif
ifneq ($(GOPATH),)
	export GOPATH := $(GOPATH):$(DEST)/gopath
else
	export GOPATH := $(DEST)/gopath
endif
DEPS=$(shell env PATH=$(PATHX) GOROOT=$(GOROOT) GOPATH=$(GOPATH) go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | grep '\.' | sort -u)
PKGS=$(shell env PATH=$(PATHX) GOROOT=$(GOROOT) GOPATH=$(GOPATH) go list ./go/... | sort -u | rev | sed -e 's,og/.*$$,,' | rev | sed -e 's,^,github.com/poppycompass/asmshell/go,')

deps: $(DEST)/gopath
	@echo "go get -u github.com/fatih/color"
	@sh -c "PATH=$(PATHX) go get -u github.com/fatih/color"
	@echo "go get -u github.com/jessevdk/go-flags"
	@sh -c "PATH=$(PATHX) go get -u github.com/jessevdk/go-flags"
	@echo "go get -u github.com/chzyer/readline"
	@sh -c "PATH=$(PATHX) go get -u github.com/chzyer/readline"
	@echo "go get -u github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	@sh -c "PATH=$(PATHX) go get -u github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	@echo "go get -u github.com/keystone-engine/keystone/bindings/go/keystone"
	@sh -c "PATH=$(PATHX) go get -u github.com/keystone-engine/keystone/bindings/go/keystone"
	@echo "go get -u github.com/poppycompass/ishell"
	@sh -c "PATH=$(PATHX) go get -u github.com/poppycompass/ishell"
	@echo "go get -u github.com/bnagy/gapstone"
	@sh -c "PATH=$(PATHX) go get -u github.com/bnagy/gapstone"
#	@echo "go get -u github.com/gorilla/websocket"
#	@sh -c "PATH=$(PATHX) go get -u github.com/gorilla/websocket"

asmshell:
	@echo "$(GOBUILD) -o asmshell ./go"
	@sh -c "PATH=$(PATHX) $(GOBUILD) -o asmshell.exe ./go"
	@echo "Generate 'asmshell.exe'"

ifeq "$(OS)" "Darwin"
	@echo "Please run 'export DYLD_LIBRARY_PATH=$${DYLD_LIBRARY_PATH}:$$(pwd)/deps/lib:$$(pwd)/deps/lib64' before wake up asmshell.exe"
else ifeq "$(OS)" "Linux"
	@echo "Please run 'export LD_LIBRARY_PATH=$${LD_LIBRARY_PATH}:$$(pwd)/deps/lib:$$(pwd)/deps/lib64' before wake up asmshell.exe"
endif
