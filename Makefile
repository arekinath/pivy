all: pivy-tool pivy-agent pivy-box


LIBRESSL_VER	= 2.7.4
LIBRESSL_URL	= https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$(LIBRESSL_VER).tar.gz

LIBRESSL_INC	= $(CURDIR)/libressl/include
LIBRESSL_LIB	= $(CURDIR)/libressl/crypto/.libs

HAVE_ZFS	:= no
USE_ZFS		?= no
HAVE_LUKS	:= no
USE_LUKS	?= no

TAR		= tar
CURL		= curl -k

prefix		?= /opt/pivy
bindir		?= $(prefix)/bin

VERSION		= 0.3.0

SECURITY_CFLAGS	= \
	-fstack-protector-all -fwrapv -fPIC \
	-D_FORTIFY_SOURCE=2 -Wall

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
	CRYPTSETUP_VER	= $(shell pkg-config --modversion libcryptsetup --silence-errors || true)
	ifneq (,$(CRYPTSETUP_VER))
		HAVE_LUKS	:= $(USE_LUKS)
		CRYPTSETUP_CFLAGS = $(shell pkg-config --cflags libcryptsetup)
		CRYPTSETUP_LIBS	= $(shell pkg-config --libs libcryptsetup)
		JSONC_CFLAGS	= $(shell pkg-config --cflags json-c)
		JSONC_LIBS	= $(shell pkg-config --libs json-c)
	else
		HAVE_LUKS	:= no
	endif
	SYSTEMDDIR	?= /usr/lib/systemd/user
endif
ifeq ($(SYSTEM), OpenBSD)
	PCSC_CFLAGS	= $(shell pkg-config --cflags libpcsclite)
	PCSC_LIBS	= $(shell pkg-config --libs libpcsclite)
	CRYPTO_CFLAGS	=
	CRYPTO_LIBS	= -lcrypto
	ZLIB_CFLAGS	=
	ZLIB_LIBS	= -lz
	SYSTEM_CFLAGS	=
	SYSTEM_LIBS	=
	RDLINE_CFLAGS	=
	RDLINE_LIBS	= -ledit
	HAVE_ZFS	:= no
	LIBCRYPTO	= /usr/lib/libcrypto.a
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
LIBCRYPTO	?= $(LIBRESSL_LIB)/libcrypto.a

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
	hmac.c			\
	authfd.c
LIBSSH_SOURCES=				\
	$(_LIBSSH_SOURCES:%=libssh/%)	\
	$(ED25519_SOURCES)		\
	$(CHAPOLY_SOURCES)

_SSS_SOURCES=			\
	hazmat.c		\
	randombytes.c
SSS_SOURCES=$(_SSS_SOURCES:%=sss/%)

PIV_COMMON_SOURCES=		\
	piv.c			\
	tlv.c			\
	debug.c			\
	bunyan.c		\
	errf.c			\
	utils.c
PIV_COMMON_HEADERS=		\
	piv.h			\
	tlv.h			\
	bunyan.h		\
	errf.h			\
	piv-internal.h		\
	debug.h			\
	utils.h

EBOX_COMMON_SOURCES=		\
	ebox.c			\
	ebox-cmd.c
EBOX_COMMON_HEADERS=		\
	ebox.h			\
	ebox-cmd.h

PIVTOOL_SOURCES=		\
	pivy-tool.c		\
	$(PIV_COMMON_SOURCES)	\
	$(LIBSSH_SOURCES)
PIVTOOL_HEADERS=		\
	$(PIV_COMMON_HEADERS)

PIVTOOL_OBJS=		$(PIVTOOL_SOURCES:%.c=%.o)
PIVTOOL_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -m64 -D_GNU_SOURCE
PIVTOOL_LDFLAGS=	-m64
PIVTOOL_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)

pivy-tool :		CFLAGS=		$(PIVTOOL_CFLAGS)
pivy-tool :		LIBS+=		$(PIVTOOL_LIBS)
pivy-tool :		LDFLAGS+=	$(PIVTOOL_LDFLAGS)
pivy-tool :		HEADERS=	$(PIVTOOL_HEADERS)

pivy-tool: $(PIVTOOL_OBJS) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVTOOL_OBJS) $(LIBS)

PIVYBOX_SOURCES=		\
	pivy-box.c		\
	$(EBOX_COMMON_SOURCES)	\
	$(PIV_COMMON_SOURCES)	\
	$(LIBSSH_SOURCES)	\
	$(SSS_SOURCES)
PIVYBOX_HEADERS=		\
	$(EBOX_COMMON_HEADERS)	\
	$(PIV_COMMON_HEADERS)

PIVYBOX_OBJS=		$(PIVYBOX_SOURCES:%.c=%.o)
PIVYBOX_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(RDLINE_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -m64 -D_GNU_SOURCE -std=gnu99
PIVYBOX_LDFLAGS=	-m64
PIVYBOX_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

pivy-box :		CFLAGS=		$(PIVYBOX_CFLAGS)
pivy-box :		LIBS+=		$(PIVYBOX_LIBS)
pivy-box :		LDFLAGS+=	$(PIVYBOX_LDFLAGS)
pivy-box :		HEADERS=	$(PIVYBOX_HEADERS)

pivy-box: $(PIVYBOX_OBJS) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVYBOX_OBJS) $(LIBS)


PIVZFS_SOURCES=			\
	pivy-zfs.c		\
	$(EBOX_COMMON_SOURCES)	\
	$(PIV_COMMON_SOURCES)	\
	$(LIBSSH_SOURCES)	\
	$(SSS_SOURCES)
PIVZFS_HEADERS=			\
	$(PIV_COMMON_HEADERS)	\
	$(EBOX_COMMON_HEADERS)

ifeq (yes, $(HAVE_ZFS))

PIVZFS_OBJS=		$(PIVZFS_SOURCES:%.c=%.o)
PIVZFS_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(LIBZFS_CFLAGS) \
			$(RDLINE_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -m64 -D_GNU_SOURCE -std=gnu99
PIVZFS_LDFLAGS=		-m64
PIVZFS_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(LIBZFS_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

pivy-zfs :		CFLAGS=		$(PIVZFS_CFLAGS)
pivy-zfs :		LIBS+=		$(PIVZFS_LIBS)
pivy-zfs :		LDFLAGS+=	$(PIVZFS_LDFLAGS)
pivy-zfs :		HEADERS=	$(PIVZFS_HEADERS)

pivy-zfs: $(PIVZFS_OBJS) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVZFS_OBJS) $(LIBS)

all: pivy-zfs

install_pivyzfs: pivy-zfs install_common
	install -o root -g wheel -m 0755 pivy-zfs $(DESTDIR)$(bindir)
install: install_pivyzfs
.PHONY: install_pivyzfs

endif

PIVYLUKS_SOURCES=		\
	pivy-luks.c		\
	$(EBOX_COMMON_SOURCES)	\
	$(PIV_COMMON_SOURCES)	\
	$(LIBSSH_SOURCES)	\
	$(SSS_SOURCES)
PIVYLUKS_HEADERS=		\
	$(PIV_COMMON_HEADERS)	\
	$(EBOX_COMMON_HEADERS)

ifeq (yes, $(HAVE_LUKS))

PIVYLUKS_OBJS=		$(PIVYLUKS_SOURCES:%.c=%.o)
PIVYLUKS_CFLAGS=	$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(CRYPTSETUP_CFLAGS) \
			$(JSONC_CFLAGS) \
			$(RDLINE_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -m64 -D_GNU_SOURCE -std=gnu99
PIVYLUKS_LDFLAGS=	-m64
PIVYLUKS_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(CRYPTSETUP_LIBS) \
			$(JSONC_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

pivy-luks :		CFLAGS=		$(PIVYLUKS_CFLAGS)
pivy-luks :		LIBS+=		$(PIVYLUKS_LIBS)
pivy-luks :		LDFLAGS+=	$(PIVYLUKS_LDFLAGS)
pivy-luks :		HEADERS=	$(PIVYLUKS_HEADERS)

pivy-luks: $(PIVYLUKS_OBJS) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVYLUKS_OBJS) $(LIBS)

all: pivy-luks

install_pivyluks: pivy-luks install_common
	install -o root -g wheel -m 0755 pivy-luks $(DESTDIR)$(bindir)
install: install_pivyluks
.PHONY: install_pivyluks

endif

AGENT_SOURCES=			\
	pivy-agent.c		\
	$(PIV_COMMON_SOURCES)	\
	$(LIBSSH_SOURCES)
AGENT_HEADERS=			\
	$(PIV_COMMON_HEADERS)

AGENT_OBJS=		$(AGENT_SOURCES:%.c=%.o)
AGENT_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -m64 -D_GNU_SOURCE
AGENT_LDFLAGS=		-m64
AGENT_LIBS=		$(PCSC_LIBS) \
			$(CRYPTO_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)

pivy-agent :		CFLAGS=		$(AGENT_CFLAGS)
pivy-agent :		LIBS+=		$(AGENT_LIBS)
pivy-agent :		LDFLAGS+=	$(AGENT_LDFLAGS)
pivy-agent :		HEADERS=	$(AGENT_HEADERS)

pivy-agent: $(AGENT_OBJS) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(AGENT_OBJS) $(LIBS)

%.o: %.c $(HEADERS) $(LIBRESSL_INC) $(LIBCRYPTO)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f pivy-tool $(PIVTOOL_OBJS)
	rm -f pivy-agent $(AGENT_OBJS)
	rm -f pivy-box $(PIVYBOX_OBJS)
	rm -f pivy-zfs $(PIVZFS_OBJS)
	rm -f pivy-luks $(PIVYLUKS_OBJS)
	rm -fr .dist
	rm -fr macosx/root macosx/*.pkg

distclean: clean
	rm -fr libressl

ifeq ($(SYSTEM), OpenBSD)
# use system libressl
else
$(LIBRESSL_INC):
	$(CURL) $(LIBRESSL_URL) | $(TAR) -zxf - && \
	    mv libressl-$(LIBRESSL_VER) libressl

$(LIBRESSL_LIB)/libcrypto.a: $(LIBRESSL_INC)
	cd libressl && \
	    ./configure --enable-static && \
	    cd crypto && $(MAKE)
endif

.PHONY: install install_common setup

.dist:
	@mkdir .dist


install_common: pivy-tool pivy-agent pivy-box
	install -o root -g wheel -m 0755 -d $(DESTDIR)$(bindir)
	install -o root -g wheel -m 0755 pivy-agent $(DESTDIR)$(bindir)
	install -o root -g wheel -m 0755 pivy-tool $(DESTDIR)$(bindir)
	install -o root -g wheel -m 0755 pivy-box $(DESTDIR)$(bindir)

ifeq ($(SYSTEM), Darwin)
install: install_common
	install -o root -g wheel -m 0755 -d $(DESTDIR)/etc/paths.d
	echo "$(bindir)" > $(DESTDIR)/etc/paths.d/pivy
	install -o root -g wheel -m 0755 -d $(DESTDIR)$(prefix)/share
	install -o root -g wheel -m 0644 macosx/net.cooperi.pivy-agent.plist \
	    $(DESTDIR)$(prefix)/share

.PHONY: package
package:
	$(MAKE) install DESTDIR=macosx/root/ prefix=/opt/pivy
	pkgbuild --root macosx/root \
	    --identifier net.cooperi.pivy \
	    --version $(VERSION) \
	    --ownership recommended \
	    --scripts macosx/scripts \
	    macosx/output.pkg
	productbuild --distribution macosx/distribution.xml \
	    --resources macosx/resources \
	    --package-path macosx \
	    --version $(VERSION) \
	    macosx/pivy-$(VERSION).pkg

.dist/net.cooperi.pivy-agent.plist: net.cooperi.pivy-agent.plist .dist pivy-tool
	@./pivy-tool list
	@printf "Enter a GUID to use for pivy-agent: "
	@read guid && \
	pkey=$$(./pivy-tool -g $${guid} pubkey 9e) && \
	cat $< | \
	    sed "s/@@GUID@@/$${guid}/g" | \
	    sed "s|@@CAK@@|$${pkey}|g" | \
	    sed "s|@@HOME@@|$${HOME}|g" > $@

setup: .dist/net.cooperi.pivy-agent.plist
	install .dist/net.cooperi.pivy-agent.plist $(HOME)/Library/LaunchAgents
	launchctl load $(HOME)/Library/LaunchAgents/net.cooperi.pivy-agent.plist
	launchctl start net.cooperi.pivy-agent
	@echo "Add the following lines to your .profile or .bashrc:"
	@echo '  export PATH=/opt/pivy/bin:$$PATH'
	@echo '  if [[ ! -e "$$SSH_AUTH_SOCK" || "$$SSH_AUTH_SOCK" == *"launchd"* ]]; then'
	@echo '    source $$HOME/.ssh/agent.env >/dev/null'
	@echo '  fi'
endif

ifeq ($(SYSTEM), Linux)
.dist/pivy-agent@.service: pivy-agent@.service .dist
	sed -e 's!@@BINDIR@@!$(bindir)!' < $< > $@
all: .dist/pivy-agent@.service

install: install_common .dist/pivy-agent@.service
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install .dist/pivy-agent\@.service $(DESTDIR)$(SYSTEMDDIR)

.dist/default_config: .dist pivy-tool
	@./pivy-tool list
	@printf "Enter a GUID to use for pivy-agent: "
	read guid && \
	pkey=$$(./pivy-tool -g $${guid} pubkey 9e | awk '{ print $$1,$$2,$$3 }') && \
	echo -e "PIV_AGENT_GUID=$${guid}\nPIV_AGENT_CAK=\"$${pkey}\"" > $@

setup: .dist/default_config
	install -d $(HOME)/.config/pivy-agent
	install .dist/default_config $(HOME)/.config/pivy-agent/default
	systemctl --user enable pivy-agent@default.service
	systemctl --user start pivy-agent@default.service
	@echo "Add the following lines to your .profile or .bashrc:"
	@echo '  export PATH=$(bindir):$$PATH'
	@echo '  if [[ ! -e "$$SSH_AUTH_SOCK" || "$$SSH_AUTH_SOCK" == *"/keyring/"* ]]; then'
	@echo '    export SSH_AUTH_SOCK="$$XDG_RUNTIME_DIR/piv-ssh-default.socket"'
	@echo '  fi'
endif
