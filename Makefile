all: piv-tool piv-agent

LIBRESSL_VER	= 2.7.4
LIBRESSL_URL	= https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$(LIBRESSL_VER).tar.gz

LIBRESSL_INC	= $(PWD)/libressl/include
LIBRESSL_LIB	= $(PWD)/libressl/crypto/.libs

HAVE_ZFS	:= no
USE_ZFS		?= yes

TAR		= tar
CURL		= curl -k

SYSTEM		:= $(shell uname -s)
ifeq ($(SYSTEM), Linux)
	PCSC_CFLAGS	= $(shell pkg-config --cflags libpcsclite)
	PCSC_LIBS	= $(shell pkg-config --libs libpcsclite)
	CRYPTO_CFLAGS	= -I$(LIBRESSL_INC)
	CRYPTO_LIBS	= $(LIBRESSL_LIB)/libcrypto.a -pthread
	ZLIB_CFLAGS	= $(shell pkg-config --cflags zlib)
	ZLIB_LIBS	= $(shell pkg-config --libs zlib)
	RDLINE_CFLAGS	= $(shell pkg-config --cflags libedit)
	RDLINE_LIBS	= $(shell pkg-config --libs libedit)
	SYSTEM_CFLAGS	= $(shell pkg-config --cflags libbsd-overlay)
	SYSTEM_LIBS	= $(shell pkg-config --libs libbsd-overlay)
	LIBZFS_VER	= $(shell pkg-config --modversion libzfs --silence-errors || true)
	ifneq (,$(LIBZFS_VER))
		HAVE_ZFS	:= $(USE_ZFS)
		LIBZFS_CFLAGS	= $(shell pkg-config --cflags libzfs)
		LIBZFS_LIBS	= $(shell pkg-config --libs libzfs) -lnvpair
	else
		HAVE_ZFS	:= no
	endif
endif
ifeq ($(SYSTEM), Darwin)
	PCSC_CFLAGS	= -I/System/Library/Frameworks/PCSC.framework/Headers/
	PCSC_LIBS	= -framework PCSC
	CRYPTO_CFLAGS	= -I$(LIBRESSL_INC)
	CRYPTO_LIBS	= $(LIBRESSL_LIB)/libcrypto.a
	ZLIB_CFLAGS	=
	ZLIB_LIBS	= -lz
	SYSTEM_CFLAGS	=
	SYSTEM_LIBS	=
	RDLINE_CFLAGS	=
	RDLINE_LIBS	= -ledit
	HAVE_ZFS	:= no
endif
ifeq ($(SYSTEM), SunOS)
	PCSC_CFLAGS	= $(shell pkg-config --cflags libpcsclite)
	PCSC_LIBS	= $(shell pkg-config --libs libpcsclite)
	CRYPTO_CFLAGS	= -I$(LIBRESSL_INC)
	CRYPTO_LIBS	= $(LIBRESSL_LIB)/libcrypto.a -pthread
	ZLIB_CFLAGS	=
	ZLIB_LIBS	= -lz
	RDLINE_CFLAGS	=
	RDLINE_LIBS	= -ltecla
	SYSTEM_CFLAGS	= -gdwarf-2 -isystem $(PROTO_AREA)/usr/include -m64 -msave-args
	SYSTEM_LIBS	= -L$(PROTO_AREA)/usr/lib -m64 -lssp -lsocket -lnsl
	HAVE_ZFS	:= $(USE_ZFS)
	LIBZFS_CFLAGS	=
	LIBZFS_LIBS	= -lzfs -lzfs_core -lnvpair
	TAR		= gtar
endif

_ED25519_SOURCES=		\
	ed25519.c		\
	fe25519.c		\
	ge25519.c		\
	sc25519.c		\
	hash.c			\
	blocks.c
ED25519_SOURCES=$(_ED25519_SOURCES:%=ed25519/%)

_CHAPOLY_SOURCES=		\
	chacha.c		\
	poly1305.c
CHAPOLY_SOURCES=$(_CHAPOLY_SOURCES:%=chapoly/%)

_LIBSSH_SOURCES=		\
	sshbuf.c		\
	sshkey.c		\
	ssh-ed25519.c		\
	ssh-ecdsa.c		\
	ssh-rsa.c		\
	cipher.c		\
	digest-openssl.c	\
	bcrypt-pbkdf.c		\
	blowfish.c		\
	rsa.c			\
	base64.c		\
	atomicio.c		\
	authfd.c
LIBSSH_SOURCES=				\
	$(_LIBSSH_SOURCES:%=libssh/%)	\
	$(ED25519_SOURCES)		\
	$(CHAPOLY_SOURCES)

_SSS_SOURCES=			\
	hazmat.c		\
	randombytes.c
SSS_SOURCES=$(_SSS_SOURCES:%=sss/%)

PIVTOOL_SOURCES=		\
	pivtool.c		\
	tlv.c			\
	piv.c			\
	debug.c			\
	bunyan.c		\
	errf.c			\
	$(LIBSSH_SOURCES)
PIVTOOL_HEADERS=		\
	tlv.h			\
	piv.h			\
	bunyan.h		\
	debug.h			\
	errf.h
PIVTOOL_OBJS=		$(PIVTOOL_SOURCES:%.c=%.o)
PIVTOOL_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			-fstack-protector-all \
			-O2 -g -m64 -fwrapv \
			-pedantic -fPIC -D_FORTIFY_SOURCE=2 \
			-Wall -D_GNU_SOURCE
PIVTOOL_LDFLAGS=	-m64
PIVTOOL_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)

piv-tool :		CFLAGS=		$(PIVTOOL_CFLAGS)
piv-tool :		LIBS+=		$(PIVTOOL_LIBS)
piv-tool :		LDFLAGS+=	$(PIVTOOL_LDFLAGS)
piv-tool :		HEADERS=	$(PIVTOOL_HEADERS)

piv-tool: $(PIVTOOL_OBJS) $(LIBRESSL_LIB)/libcrypto.a
	$(CC) $(LDFLAGS) -o $@ $(PIVTOOL_OBJS) $(LIBS)

EBOX_SOURCES=			\
	ebox-cmd.c		\
	ebox.c			\
	tlv.c			\
	piv.c			\
	debug.c			\
	bunyan.c		\
	errf.c			\
	$(LIBSSH_SOURCES)	\
	$(SSS_SOURCES)
EBOX_HEADERS=			\
	ebox.h			\
	tlv.h			\
	piv.h			\
	bunyan.h		\
	errf.h			\
	debug.h

EBOX_OBJS=		$(EBOX_SOURCES:%.c=%.o)
EBOX_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(RDLINE_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			-fstack-protector-all \
			-O2 -g -m64 -fwrapv \
			-fPIC -D_FORTIFY_SOURCE=2 \
			-Wall -D_GNU_SOURCE -std=gnu99
EBOX_LDFLAGS=		-m64
EBOX_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

ebox :		CFLAGS=		$(EBOX_CFLAGS)
ebox :		LIBS+=		$(EBOX_LIBS)
ebox :		LDFLAGS+=	$(EBOX_LDFLAGS)
ebox :		HEADERS=	$(EBOX_HEADERS)

ebox: $(EBOX_OBJS) $(LIBRESSL_LIB)/libcrypto.a
	$(CC) $(LDFLAGS) -o $@ $(EBOX_OBJS) $(LIBS)

all: ebox


PIVZFS_SOURCES=			\
	piv-zfs.c		\
	tlv.c			\
	piv.c			\
	debug.c			\
	bunyan.c		\
	json.c			\
	custr.c			\
	errf.c			\
	$(LIBSSH_SOURCES)	\
	$(SSS_SOURCES)
PIVZFS_HEADERS=			\
	tlv.h			\
	piv.h			\
	bunyan.h		\
	json.h			\
	errf.h			\
	custr.h			\
	debug.h

ifeq (yes, $(HAVE_ZFS))

PIVZFS_OBJS=		$(PIVZFS_SOURCES:%.c=%.o)
PIVZFS_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(LIBZFS_CFLAGS) \
			$(RDLINE_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			-fstack-protector-all \
			-O2 -g -m64 -fwrapv \
			-fPIC -D_FORTIFY_SOURCE=2 \
			-Wall -D_GNU_SOURCE -std=gnu99
PIVZFS_LDFLAGS=		-m64
PIVZFS_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(LIBZFS_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

piv-zfs :		CFLAGS=		$(PIVZFS_CFLAGS)
piv-zfs :		LIBS+=		$(PIVZFS_LIBS)
piv-zfs :		LDFLAGS+=	$(PIVZFS_LDFLAGS)
piv-zfs :		HEADERS=	$(PIVZFS_HEADERS)

piv-zfs: $(PIVZFS_OBJS) $(LIBRESSL_LIB)/libcrypto.a
	$(CC) $(LDFLAGS) -o $@ $(PIVZFS_OBJS) $(LIBS)

all: piv-zfs

endif

AGENT_SOURCES=			\
	agent.c			\
	tlv.c			\
	piv.c			\
	debug.c			\
	bunyan.c		\
	errf.c			\
	$(LIBSSH_SOURCES)
AGENT_HEADERS=		\
	tlv.h			\
	piv.h			\
	bunyan.h		\
	errf.h			\
	debug.h
AGENT_OBJS=		$(AGENT_SOURCES:%.c=%.o)
AGENT_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			-fstack-protector-all \
			-O2 -g -m64 -fwrapv \
			-pedantic -fPIC -D_FORTIFY_SOURCE=2 \
			-Wall -D_GNU_SOURCE
AGENT_LDFLAGS=		-m64
AGENT_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)

piv-agent :		CFLAGS=		$(AGENT_CFLAGS)
piv-agent :		LIBS+=		$(AGENT_LIBS)
piv-agent :		LDFLAGS+=	$(AGENT_LDFLAGS)
piv-agent :		HEADERS=	$(AGENT_HEADERS)

piv-agent: $(AGENT_OBJS) $(LIBRESSL_LIB)/libcrypto.a
	$(CC) $(LDFLAGS) -o $@ $(AGENT_OBJS) $(LIBS)

%.o: %.c $(HEADERS) $(LIBRESSL_INC)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f piv-tool $(PIVTOOL_OBJS)
	rm -f piv-agent $(AGENT_OBJS)
	rm -f piv-zfs $(PIVZFS_OBJS)
	rm -fr .dist

distclean: clean
	rm -fr libressl

$(LIBRESSL_INC):
	$(CURL) $(LIBRESSL_URL) | $(TAR) -zxf - && \
	    mv libressl-$(LIBRESSL_VER) libressl

$(LIBRESSL_LIB)/libcrypto.a: $(LIBRESSL_INC)
	cd libressl && \
	    ./configure --enable-static && \
	    $(MAKE)

.PHONY: install

.dist:
	@mkdir .dist

ifeq ($(SYSTEM), Darwin)
.dist/net.cooperi.piv-agent.plist: net.cooperi.piv-agent.plist .dist piv-tool
	@./piv-tool list
	@printf "Enter a GUID to use for piv-agent: "
	@read guid && \
	pkey=$$(./piv-tool -g $${guid} pubkey 9e) && \
	cat $< | \
	    sed "s/@@GUID@@/$${guid}/g" | \
	    sed "s|@@CAK@@|$${pkey}|g" | \
	    sed "s|@@HOME@@|$${HOME}|g" > $@

install: .dist/net.cooperi.piv-agent.plist piv-tool piv-agent
	sudo install -o root -g wheel -m 0755 -d /opt/piv-agent/bin
	sudo install -o root -g wheel -m 0755 piv-agent piv-tool  /opt/piv-agent/bin
	install .dist/net.cooperi.piv-agent.plist $(HOME)/Library/LaunchAgents
	launchctl load $(HOME)/Library/LaunchAgents/net.cooperi.piv-agent.plist
	launchctl start net.cooperi.piv-agent
	@echo "Add the following lines to your .profile or .bashrc:"
	@echo '  export PATH=/opt/piv-agent/bin:$$PATH'
	@echo '  if [[ ! -e "$$SSH_AUTH_SOCK" || "$$SSH_AUTH_SOCK" == *"launchd"* ]]; then'
	@echo '    source $$HOME/.ssh/agent.env >/dev/null'
	@echo '  fi'
endif

ifeq ($(SYSTEM), Linux)
.dist/piv-agent.service: piv-agent.service .dist piv-tool
	@./piv-tool list
	@printf "Enter a GUID to use for piv-agent: "
	@read guid && \
	pkey=$$(./piv-tool -g $${guid} pubkey 9e) && \
	cat $< | \
	    sed "s/@@GUID@@/$${guid}/g" | \
	    sed "s|@@CAK@@|$${pkey}|g" > $@

install: .dist/piv-agent.service piv-tool piv-agent
	sudo install -o root -g wheel -m 0755 -d /opt/piv-agent/bin
	sudo install -o root -g wheel -m 0755 piv-agent piv-tool  /opt/piv-agent/bin
	install -d $(HOME)/.config/systemd/user
	install .dist/piv-agent.service $(HOME)/.config/systemd/user
	systemctl --user enable piv-agent.service
	systemctl --user start piv-agent.service
	@echo "Add the following lines to your .profile or .bashrc:"
	@echo '  export PATH=/opt/piv-agent/bin:$$PATH'
	@echo '  if [[ ! -e "$$SSH_AUTH_SOCK" || "$$SSH_AUTH_SOCK" == *"/keyring/"* ]]; then'
	@echo '    export SSH_AUTH_SOCK="$$XDG_RUNTIME_DIR/ssh-agent.socket"'
	@echo '  fi'
endif
