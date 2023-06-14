all: pivy-tool pivy-agent pivy-box

LIBRESSL_VER	= 3.7.0
LIBRESSL_URL	= https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$(LIBRESSL_VER).tar.gz

OPENSSH_VER	= 9.2p1
OPENSSH_URL	= https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$(OPENSSH_VER).tar.gz

OPENSSH		= $(CURDIR)/openssh
LIBRESSL	= $(CURDIR)/libressl
LIBRESSL_INC	= $(CURDIR)/libressl/include
LIBRESSL_LIB	= $(CURDIR)/libressl/crypto/.libs

HAVE_ZFS	:= no
USE_ZFS		?= no
HAVE_LUKS	:= no
USE_LUKS	?= no
HAVE_PAM	:= no
USE_PAM		?= no
HAVE_JSONC	:= no
USE_JSONC	?= no
HAVE_CTF	:= no

TAR		= tar
CURL		= curl

prefix		?= /opt/pivy
bindir		?= $(prefix)/bin
libdir		?= $(prefix)/lib
binowner	?= root
bingroup	?= wheel

VERSION		= 0.11.1

INSTALL		?= install
INSTALLBIN	?= $(INSTALL) -o $(binowner) -g $(bingroup) -m 0755

SECURITY_CFLAGS	= \
	-fstack-protector-all -fwrapv -fPIC \
	-D_FORTIFY_SOURCE=2 -Wall -g -O2 -gdwarf-2

SYSTEM		:= $(shell uname -s)
ifeq ($(SYSTEM), Linux)
	PCSC_CFLAGS	= $(shell pkg-config --cflags libpcsclite)
	PCSC_LIBS	= $(shell pkg-config --libs libpcsclite)
	CRYPTO_CFLAGS	= -I$(LIBRESSL_INC)
	CRYPTO_LDFLAGS	= -L$(LIBRESSL_LIB)
	CRYPTO_LIBS	= -L$(LIBRESSL_LIB) -lcrypto -pthread
	ZLIB_CFLAGS	= $(shell pkg-config --cflags zlib)
	ZLIB_LIBS	= $(shell pkg-config --libs zlib)
	RDLINE_CFLAGS	= $(shell pkg-config --cflags libedit)
	RDLINE_LIBS	= $(shell pkg-config --libs libedit)
	SYSTEM_CFLAGS	= $(shell pkg-config --cflags libbsd-overlay)
	SYSTEM_CFLAGS	+=		\
		-DHAVE_USER_FROM_UID	\
		-DHAVE_STRMODE		\
		-DHAVE_GROUP_FROM_GID
	OPTIM_CFLAGS	= -flto
	OPTIM_LDFLAGS	= -O0 -flto
	SYSTEM_LIBS	= $(shell pkg-config --libs libbsd-overlay)
	SYSTEM_LDFLAGS	= $(SYSTEM_LIBS)
	LIBZFS_VER	= $(shell pkg-config --modversion libzfs --silence-errors || true)
	ifneq (,$(LIBZFS_VER))
		HAVE_ZFS	:= $(USE_ZFS)
		LIBZFS_CFLAGS	= $(shell pkg-config --cflags libzfs)
		LIBZFS_CFLAGS	+= -DUSING_SPL
		LIBZFS_LIBS	= $(shell pkg-config --libs libzfs) -lnvpair
	else
		HAVE_ZFS	:= no
	endif
	CRYPTSETUP_VER	= $(shell pkg-config --modversion libcryptsetup --silence-errors || true)
	ifneq (,$(CRYPTSETUP_VER))
		HAVE_LUKS	:= $(USE_LUKS)
		CRYPTSETUP_CFLAGS = $(shell pkg-config --cflags libcryptsetup)
		CRYPTSETUP_LIBS	= $(shell pkg-config --libs libcryptsetup)
	else
		HAVE_LUKS	:= no
	endif
	JSONC_VER	= $(shell pkg-config --modversion json-c --silence-errors || true)
	ifneq (,$(JSONC_VER))
		HAVE_JSONC	:= $(USE_JSONC)
		JSONC_CFLAGS	= $(shell pkg-config --cflags json-c)
		JSONC_LIBS	= $(shell pkg-config --libs json-c)
		JSONC_14	= $(shell pkg-config --exists --atleast-version=0.14 json-c --silence-errors && echo yes)
		ifeq (yes,$(JSONC_14))
			JSONC_CFLAGS	+= -DJSONC_14
		endif
	else
		HAVE_JSONC	:= no
	endif
	ifeq (yes,$(USE_PAM))
		SYSTEM_CFLAGS	+= -fPIC
	endif
	HAVE_PAM	:= $(USE_PAM)
	PAM_CFLAGS	= -fPIC
	PAM_LIBS	= -lpam
	PAM_PLUGINDIR	?= $(libdir)/security
	SYSTEMDDIR	?= $(libdir)/systemd/user
	tpl_user_dir	?= "$$HOME/.config/pivy/tpl/$$TPL"
	tpl_system_dir	?= "/etc/pivy/tpl/$$TPL"
endif
ifeq ($(SYSTEM), OpenBSD)
	PCSC_CFLAGS	?= $(shell pkg-config --cflags libpcsclite)
	PCSC_LIBS	?= $(shell pkg-config --libs libpcsclite)
	CRYPTO_CFLAGS	=
	CRYPTO_LIBS	= -lcrypto
	ZLIB_CFLAGS	=
	ZLIB_LIBS	= -lz
	SYSTEM_CFLAGS	=
	SYSTEM_LIBS	= -lutil
	SYSTEM_LDFLAGS	=
	RDLINE_CFLAGS	=
	RDLINE_LIBS	= -ledit
	HAVE_ZFS	:= no
	LIBCRYPTO	= /usr/lib/libcrypto.a
	HAVE_PAM	:= no
	JSONC_VER	= $(shell pkg-config --modversion json-c --silence-errors || true)
	ifneq (,$(JSONC_VER))
		HAVE_JSONC	:= $(USE_JSONC)
		JSONC_CFLAGS	= $(shell pkg-config --cflags json-c)
		JSONC_LIBS	= $(shell pkg-config --libs json-c)
		JSONC_14	= $(shell pkg-config --exists --atleast-version=0.14 json-c --silence-errors && echo yes)
		ifeq (yes,$(JSONC_14))
			JSONC_CFLAGS	+= -DJSONC_14
		endif
	else
		HAVE_JSONC	:= no
	endif
endif
ifeq ($(SYSTEM), Darwin)
	PCSC_CFLAGS	= -I/System/Library/Frameworks/PCSC.framework/Headers/
	PCSC_LIBS	= -framework PCSC
	CRYPTO_CFLAGS	= -I$(LIBRESSL_INC)
	CRYPTO_LIBS	= -L$(LIBRESSL_LIB) -lcrypto
	CRYPTO_LDFLAGS	= -L$(LIBRESSL_LIB)
	ZLIB_CFLAGS	=
	ZLIB_LIBS	= -lz
	SYSTEM_CFLAGS	= -arch x86_64 -arch arm64
	SYSTEM_LIBS	= -lproc
	SYSTEM_LDFLAGS	= -arch x86_64 -arch arm64
	RDLINE_CFLAGS	=
	RDLINE_LIBS	= -ledit
	HAVE_ZFS	:= no
	HAVE_PAM	:= no
	tpl_user_dir	?= "$$HOME/Library/Preferences/pivy/tpl/$$TPL"
	tpl_system_dir	?= "/Library/Preferences/pivy/tpl/$$TPL"
endif
ifeq ($(SYSTEM), SunOS)
	PCSC_CFLAGS	?= $(shell pkg-config --cflags libpcsclite)
	PCSC_LIBS	?= $(shell pkg-config --libs libpcsclite)
	CRYPTO_CFLAGS	= -I$(LIBRESSL_INC)
	CRYPTO_LIBS	= -Wl,-Bstatic -L$(LIBRESSL_LIB) -lcrypto -Wl,-Bdynamic -pthread
	CRYPTO_LDFLAGS	= -Wl,-Bstatic -L$(LIBRESSL_LIB) -lcrypto -Wl,-Bdynamic
	ZLIB_CFLAGS	=
	ZLIB_LIBS	= -lz
	RDLINE_CFLAGS	=
	RDLINE_LIBS	= -ltecla
	SYSTEM_CFLAGS	= -gdwarf-2
	ifdef PROTO_AREA
		SYSTEM_CFLAGS	+= -isystem $(PROTO_AREA)/usr/include
	endif
	SYSTEM_CFLAGS	+= -m64 -msave-args
	SYSTEM_CFLAGS	+= -Du_int8_t=uint8_t -Du_int16_t=uint16_t \
		-Du_int32_t=uint32_t -Du_int64_t=uint64_t

	# feature tests, who likes 'em
	SYSTEM_CFLAGS	+= -D_XOPEN_SOURCE=600
	SYSTEM_CFLAGS	+= -D__EXTENSIONS__ -D_REENTRANT

	SYSTEM_LIBS	= -L$(PROTO_AREA)/usr/lib/64 -lssp -lsocket -lnsl
	SYSTEM_LDFLAGS	= -m64 -L$(PROTO_AREA)/usr/lib/64

	HAVE_ZFS	:= $(USE_ZFS)
	ifdef ILLUMOS_SRC
		LIBZFS_CFLAGS	= -I$(ILLUMOS_SRC)/uts/common/fs/zfs	# for spa_impl.h
		LIBZFS_CFLAGS	+= -I$(ILLUMOS_SRC)/common/zfs		# for zfeature_common.h
	else
		LIBZFS_CFLAGS	= -I$(ZFS_PRIVATE_HEADERS)
	endif
	LIBZFS_LIBS	= -lzfs -lzfs_core -lnvpair

	TAR		= gtar
	HAVE_PAM	:= no
	JSONC_VER	= $(shell pkg-config --modversion json-c --silence-errors || true)
	ifneq (,$(JSONC_VER))
		HAVE_JSONC	:= $(USE_JSONC)
		JSONC_CFLAGS	= $(shell pkg-config --cflags json-c)
		JSONC_LIBS	= $(shell pkg-config --libs json-c)
		JSONC_14	= $(shell pkg-config --exists --atleast-version=0.14 json-c --silence-errors && echo yes)
		ifeq (yes,$(JSONC_14))
			JSONC_CFLAGS	+= -DJSONC_14
		endif
	else
		HAVE_JSONC	:= no
	endif

	CTFCONVERT	?= ctfconvert
	CTFOPTS		?= -k
	CTFCONV_HELP	= $(shell $(CTFCONVERT) -h 2>&1 | fgrep -- -o | fgrep "add CTF")
	ifneq (,$(CTFCONV_HELP))
		HAVE_CTF	:= yes
	endif

	SMF_METHODS	?= $(prefix)/lib/svc/method
	SMF_MANIFESTS	?= $(prefix)/lib/svc/manifest
endif
LIBCRYPTO	?= $(LIBRESSL_LIB)/libcrypto.a
LIBSSH		?= $(OPENSSH)/libssh.a

tpl_user_dir	?= "$$HOME/.pivy/tpl/$$TPL"
tpl_system_dir	?= "/etc/pivy/tpl/$$TPL"

CONFIG_CFLAGS	=  -DEBOX_USER_TPL_PATH='$(tpl_user_dir)'
CONFIG_CFLAGS	+= -DEBOX_SYSTEM_TPL_PATH='$(tpl_system_dir)'

_ED25519_SOURCES=		\
	ed25519.c		\
	hash.c

_CHAPOLY_SOURCES=		\
	chacha.c		\
	poly1305.c

_OBSD_COMPAT=			\
	blowfish.c		\
	bcrypt_pbkdf.c		\
	base64.c		\
	bsd-setres_id.c		\
	vis.c			\

_LIBSSH_SOURCES=		\
	sshbuf.c		\
	sshbuf-getput-basic.c	\
	sshbuf-getput-crypto.c	\
	sshbuf-misc.c		\
	sshkey.c		\
	ssh-ed25519.c		\
	ssh-ecdsa.c		\
	ssh-rsa.c		\
	ssh-dss.c		\
	cipher.c		\
	cipher-chachapoly.c	\
	cipher-chachapoly-libcrypto.c \
	digest-openssl.c	\
	atomicio.c		\
	hmac.c			\
	authfd.c		\
	misc.c			\
	match.c			\
	ssh-sk.c		\
	log.c			\
	fatal.c			\
	xmalloc.c		\
	addrmatch.c		\
	addr.c			\
	$(_ED25519_SOURCES)	\
	$(_CHAPOLY_SOURCES)	\
	$(_OBSD_COMPAT:%=openbsd-compat/%)
LIBSSH_SOURCES=				\
	$(_LIBSSH_SOURCES:%=$(OPENSSH)/%)

LIBSSH_OBJS=		$(LIBSSH_SOURCES:%.c=%.o)
LIBSSH_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(JSONC_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			$(CONFIG_CFLAGS) \
			-O2 -g -D_GNU_SOURCE \
			-I$(OPENSSH) \
			-DPIVY_VERSION='"$(VERSION)"'
LIBSSH_LDFLAGS=		$(SYSTEM_LDFLAGS) \
			$(CRYPTO_LDFLAGS)
LIBSSH_HEADERS=

$(LIBSSH):		CFLAGS=		$(LIBSSH_CFLAGS)
$(LIBSSH):		LDFLAGS+=	$(LIBSSH_LDFLAGS)
$(LIBSSH):		HEADERS=	$(LIBSSH_HEADERS)
$(LIBSSH): $(LIBSSH_OBJS)
	$(AR) rcs $@ $(LIBSSH_OBJS)

$(LIBSSH_SOURCES): .openssh.configure
$(LIBSSH_OBJS): .openssh.configure

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
	utils.h			\

ifneq ($(SYSTEM), OpenBSD)
PIV_COMMON_SOURCES+= 	readpassphrase.c
endif

PIV_CERT_SOURCES=			\
	piv-certs.c		\
	pkinit_asn1.c
PIV_CERT_HEADERS=			\
	piv-ca.h		\
	pkinit_asn1.h

EBOX_COMMON_SOURCES=		\
	ebox.c			\
	ebox-cmd.c
EBOX_COMMON_HEADERS=		\
	ebox.h			\
	ebox-cmd.h

PIVTOOL_SOURCES=		\
	pivy-tool.c		\
	$(PIV_COMMON_SOURCES)	\
	$(PIV_CERT_SOURCES)
PIVTOOL_HEADERS=		\
	$(PIV_COMMON_HEADERS)	\
	$(PIV_CERT_HEADERS)

PIVTOOL_OBJS=		$(PIVTOOL_SOURCES:%.c=%.o)
PIVTOOL_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(OPTIM_CFLAGS) \
			-O2 -g -D_GNU_SOURCE \
			-DPIVY_VERSION='"$(VERSION)"'
PIVTOOL_LDFLAGS=	$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
PIVTOOL_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)

pivy-tool :		CFLAGS=		$(PIVTOOL_CFLAGS)
pivy-tool :		LIBS+=		$(PIVTOOL_LIBS)
pivy-tool :		LDFLAGS+=	$(PIVTOOL_LDFLAGS)
pivy-tool :		HEADERS=	$(PIVTOOL_HEADERS)

pivy-tool: $(PIVTOOL_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVTOOL_OBJS) $(LIBSSH) $(LIBS)

LIBPIVY_SOURCES=		\
	$(PIV_COMMON_SOURCES)	\
	$(PIV_CERT_SOURCES)	\
	cleanup-exit.c
LIBPIVY_HEADERS=		\
	$(PIV_COMMON_HEADERS)	\
	$(PIV_CERT_HEADERS)
ifeq (yes, $(HAVE_JSONC))
	LIBPIVY_SOURCES+=	piv-ca.c
	LIBPIVY_HEADERS+=	$(PIV_CA_HEADERS)
endif
LIBPIVY_OBJS=		$(LIBPIVY_SOURCES:%.c=%.o)
LIBPIVY_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(OPTIM_CFLAGS) \
			-O2 -g -D_GNU_SOURCE \
			-fPIC \
			-DPIVY_VERSION='"$(VERSION)"'
LIBPIVY_LDFLAGS=	$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS) \
			-Wl,--version-script=libpivy.version
LIBPIVY_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)
ifeq (yes, $(HAVE_JSONC))
	LIBPIVY_CFLAGS+= $(JSONC_CFLAGS)
	LIBPIVY_LIBS+=	$(JSONC_LIBS)
endif

libpivy.so.1 :		CFLAGS=		$(LIBPIVY_CFLAGS)
libpivy.so.1 :		LIBS+=		$(LIBPIVY_LIBS)
libpivy.so.1 :		LDFLAGS+=	$(LIBPIVY_LDFLAGS)
libpivy.so.1 :		HEADERS=	$(LIBPIVY_HEADERS)

libpivy.so.1: $(LIBPIVY_OBJS) $(LIBSSH) $(LIBCRYPTO) libpivy.version
	$(CC) $(LDFLAGS) -shared -o $@ $(LIBPIVY_OBJS) $(LIBSSH) $(LIBS)

libpivy.so: libpivy.so.1
	ln -sf libpivy.so.1 libpivy.so

ifeq (yes, $(HAVE_JSONC))

PIVYCA_SOURCES=			\
	pivy-ca.c		\
	piv-ca.c		\
	$(PIV_COMMON_SOURCES)	\
	$(PIV_CERT_SOURCES)	\
	$(EBOX_COMMON_SOURCES)	\
	$(SSS_SOURCES)
PIVYCA_HEADERS=			\
	$(EBOX_COMMON_HEADERS)	\
	$(PIV_COMMON_HEADERS)	\
	$(PIV_CA_HEADERS)

PIVYCA_OBJS=		$(PIVYCA_SOURCES:%.c=%.o)

PIVYCA_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(RDLINE_CFLAGS) \
			$(JSONC_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(OPTIM_CFLAGS) \
			$(SECURITY_CFLAGS) \
			$(CONFIG_CFLAGS) \
			-O0 -g -gdwarf-2 -D_GNU_SOURCE \
			-DPIVY_VERSION='"$(VERSION)"'
PIVYCA_LDFLAGS=		$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
PIVYCA_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(RDLINE_LIBS) \
			$(JSONC_LIBS) \
			$(SYSTEM_LIBS)

pivy-ca :		CFLAGS=		$(PIVYCA_CFLAGS)
pivy-ca :		LIBS+=		$(PIVYCA_LIBS)
pivy-ca :		LDFLAGS+=	$(PIVYCA_LDFLAGS)
pivy-ca :		HEADERS=	$(PIVYCA_HEADERS)

pivy-ca: $(PIVYCA_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVYCA_OBJS) $(LIBSSH) $(LIBS)

all: pivy-ca

install_pivyca: pivy-ca install_common
	$(INSTALLBIN) pivy-ca $(DESTDIR)$(bindir)
install: install_pivyca
.PHONY: install_pivyca

.ctfconvert.ca: pivy-ca
	$(CTFCONVERT) $(CTFOPTS) pivy-ca && touch $@
.ctfconvert: .ctfconvert.ca

endif

PIVYBOX_SOURCES=		\
	pivy-box.c		\
	$(EBOX_COMMON_SOURCES)	\
	$(PIV_COMMON_SOURCES)	\
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
			$(OPTIM_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -D_GNU_SOURCE -std=gnu99
PIVYBOX_LDFLAGS=	$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
PIVYBOX_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

pivy-box :		CFLAGS=		$(PIVYBOX_CFLAGS)
pivy-box :		LIBS+=		$(PIVYBOX_LIBS)
pivy-box :		LDFLAGS+=	$(PIVYBOX_LDFLAGS)
pivy-box :		HEADERS=	$(PIVYBOX_HEADERS)

pivy-box: $(PIVYBOX_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVYBOX_OBJS) $(LIBSSH) $(LIBS)


PIVZFS_SOURCES=			\
	pivy-zfs.c		\
	$(EBOX_COMMON_SOURCES)	\
	$(PIV_COMMON_SOURCES)	\
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
			$(OPTIM_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -D_GNU_SOURCE -std=gnu99
PIVZFS_LDFLAGS=		$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
PIVZFS_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(LIBZFS_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

pivy-zfs :		CFLAGS=		$(PIVZFS_CFLAGS)
pivy-zfs :		LIBS+=		$(PIVZFS_LIBS)
pivy-zfs :		LDFLAGS+=	$(PIVZFS_LDFLAGS)
pivy-zfs :		HEADERS=	$(PIVZFS_HEADERS)

pivy-zfs: $(PIVZFS_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVZFS_OBJS) $(LIBSSH) $(LIBS)

all: pivy-zfs

install_pivyzfs: pivy-zfs install_common
	$(INSTALLBIN) pivy-zfs $(DESTDIR)$(bindir)
install: install_pivyzfs
.PHONY: install_pivyzfs

.ctfconvert.zfs: pivy-zfs
	$(CTFCONVERT) $(CTFOPTS) pivy-zfs && touch $@
.ctfconvert: .ctfconvert.zfs

endif

PIVYLUKS_SOURCES=		\
	pivy-luks.c		\
	$(EBOX_COMMON_SOURCES)	\
	$(PIV_COMMON_SOURCES)	\
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
			$(OPTIM_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -D_GNU_SOURCE -std=gnu99
PIVYLUKS_LDFLAGS=	$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
PIVYLUKS_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(CRYPTSETUP_LIBS) \
			$(JSONC_LIBS) \
			$(RDLINE_LIBS) \
			$(SYSTEM_LIBS)

pivy-luks :		CFLAGS=		$(PIVYLUKS_CFLAGS)
pivy-luks :		LIBS+=		$(PIVYLUKS_LIBS)
pivy-luks :		LDFLAGS+=	$(PIVYLUKS_LDFLAGS)
pivy-luks :		HEADERS=	$(PIVYLUKS_HEADERS)

pivy-luks: $(PIVYLUKS_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(PIVYLUKS_OBJS) $(LIBSSH) $(LIBS)

all: pivy-luks

install_pivyluks: pivy-luks install_common
	$(INSTALLBIN) pivy-luks $(DESTDIR)$(bindir)
install: install_pivyluks
.PHONY: install_pivyluks

endif

PAMPIVY_SOURCES=		\
	pam_pivy.c		\
	$(PIV_COMMON_SOURCES)
PAMPIVY_HEADERS=		\
	$(PIV_COMMON_HEADERS)	\

ifeq (yes, $(HAVE_PAM))

PAMPIVY_OBJS=		$(PAMPIVY_SOURCES:%.c=%.o)
PAMPIVY_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(PAM_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(OPTIM_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -D_GNU_SOURCE -std=gnu99
PAMPIVY_LDFLAGS=	$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
PAMPIVY_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(PAM_LIBS) \
			$(SYSTEM_LIBS)

pam_pivy.so :		CFLAGS=		$(PAMPIVY_CFLAGS)
pam_pivy.so :		LIBS+=		$(PAMPIVY_LIBS)
pam_pivy.so :		LDFLAGS+=	$(PAMPIVY_LDFLAGS)
pam_pivy.so :		HEADERS=	$(PAMPIVY_HEADERS)

pam_pivy.so: $(PAMPIVY_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) -shared -o $@ $(LDFLAGS) \
	    -Wl,--version-script=pam_pivy.version $(PAMPIVY_OBJS) \
	    $(LIBSSH) $(LIBS)

all: pam_pivy.so

install_pampivy: pam_pivy.so install_common
	$(INSTALLBIN) -d $(DESTDIR)$(PAM_PLUGINDIR)
	$(INSTALLBIN) pam_pivy.so $(DESTDIR)$(PAM_PLUGINDIR)
install: install_pampivy
.PHONY: install_pampivy

endif

AGENT_SOURCES=			\
	pivy-agent.c		\
	$(PIV_COMMON_SOURCES)
AGENT_HEADERS=			\
	$(PIV_COMMON_HEADERS)

AGENT_OBJS=		$(AGENT_SOURCES:%.c=%.o)
AGENT_CFLAGS=		$(PCSC_CFLAGS) \
			$(CRYPTO_CFLAGS) \
			$(ZLIB_CFLAGS) \
			$(SYSTEM_CFLAGS) \
			$(OPTIM_CFLAGS) \
			$(CONFIG_CFLAGS) \
			$(SECURITY_CFLAGS) \
			-O2 -g -D_GNU_SOURCE
AGENT_LDFLAGS=		$(SYSTEM_LDFLAGS) \
			$(OPTIM_LDFLAGS)
AGENT_LIBS=		$(CRYPTO_LIBS) \
			$(PCSC_LIBS) \
			$(ZLIB_LIBS) \
			$(SYSTEM_LIBS)

pivy-agent :		CFLAGS=		$(AGENT_CFLAGS)
pivy-agent :		LIBS+=		$(AGENT_LIBS)
pivy-agent :		LDFLAGS+=	$(AGENT_LDFLAGS)
pivy-agent :		HEADERS=	$(AGENT_HEADERS)

pivy-agent: $(AGENT_OBJS) $(LIBSSH) $(LIBCRYPTO)
	$(CC) $(LDFLAGS) -o $@ $(AGENT_OBJS) $(LIBSSH) $(LIBS)

%.o: %.c $(HEADERS) .openssh.configure $(LIBCRYPTO)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f pivy-tool $(PIVTOOL_OBJS)
	rm -f pivy-agent $(AGENT_OBJS)
	rm -f pivy-box $(PIVYBOX_OBJS)
	rm -f pivy-zfs $(PIVZFS_OBJS)
	rm -f pivy-luks $(PIVYLUKS_OBJS)
	rm -f pivy-ca $(PIVYCA_OBJS)
	rm -f pam_pivy.so $(PAMPIVY_OBJS)
	rm -f libpivy.so libpivy.so.1 $(LIBPIVY_OBJS)
	rm -fr .dist
	rm -fr macosx/root macosx/*.pkg

distclean: clean
	rm -fr libressl .libressl.extract .libressl.patch .libressl.configure
	rm -fr openssh .openssh.extract .openssh.patch .openssh.configure

.openssh.extract:
	$(CURL) $(OPENSSH_URL) | $(TAR) -zxf - && \
	    mv openssh-$(OPENSSH_VER) openssh && \
	    touch $(CURDIR)/$@

OPENSSH_PATCHES	= openssh.patch
ifeq ($(SYSTEM),SunOS)
	OPENSSH_PATCHES	+= openssh-sunos.patch
endif
.openssh.patch: .openssh.extract
	for PATCH in $(OPENSSH_PATCHES); do \
	    patch -p0 <$$PATCH; \
	    done && \
	    touch $(CURDIR)/$@

OPENSSH_CONFIG_ARGS=	\
	--disable-security-key \
	--disable-pkcs11

.openssh.configure: .openssh.patch $(LIBCRYPTO)
	cd openssh && \
	    CFLAGS="$(LIBSSH_CFLAGS)" LDFLAGS="$(LIBSSH_LDFLAGS)" \
	    ./configure $(OPENSSH_CONFIG_ARGS) && \
	    touch $(CURDIR)/$@

ifeq ($(SYSTEM), OpenBSD)
# use system libressl
else
.libressl.extract:
	$(CURL) $(LIBRESSL_URL) | $(TAR) -zxf - && \
	    mv libressl-$(LIBRESSL_VER) libressl && \
	    touch $(CURDIR)/$@

ifeq ($(SYSTEM), Darwin)
.libressl.patch: .libressl.extract
	# patch out some x86-specific stuff that will break us cross-compiling
	# for arm64 on macos
	cp libressl/crypto/Makefile.in{,.bak} && \
	    grep -v HOST_CPU_IS_INTEL libressl/crypto/Makefile.in.bak \
	    > libressl/crypto/Makefile.in && \
	    patch -p0 <libressl.patch && \
	    touch $(CURDIR)/$@
else
.libressl.patch: .libressl.extract
	patch -p0 <libressl.patch && \
	    touch $(CURDIR)/$@
endif

LIBRESSL_CONFIG_ARGS=	\
	--enable-static
ifeq ($(SYSTEM), Darwin)
	# making a universal binary on macos with the asm bits is hard
	# let's go shopping (pivy doesn't need super fast crypto anyway)
	LIBRESSL_CONFIG_ARGS+=	--disable-asm
endif
OPENSSH_CONFIG_ARGS+=	\
	--with-ssl-dir=$(LIBRESSL)

.libressl.configure: .libressl.patch
	cd libressl && \
	    CFLAGS="-fPIC $(SYSTEM_CFLAGS)" LDFLAGS="$(SYSTEM_LDFLAGS)" \
	    ./configure $(LIBRESSL_CONFIG_ARGS) && \
	    touch $(CURDIR)/$@

$(LIBRESSL_LIB)/libcrypto.a: .libressl.configure
	cd libressl/crypto && \
	    $(MAKE) && \
	    rm -f $(LIBRESSL_LIB)/*.so $(LIBRESSL_LIB)/*.so.* $(LIBRESSL_LIB)/*.dylib

endif

.PHONY: install install_common setup

.dist:
	@mkdir .dist


install_common: pivy-tool pivy-agent pivy-box
	$(INSTALLBIN) -d $(DESTDIR)$(bindir)
	$(INSTALLBIN) pivy-agent $(DESTDIR)$(bindir)
	$(INSTALLBIN) pivy-tool $(DESTDIR)$(bindir)
	$(INSTALLBIN) pivy-box $(DESTDIR)$(bindir)

ifeq ($(SYSTEM), Darwin)
install: install_common
	$(INSTALLBIN) -d $(DESTDIR)/etc/paths.d
	echo "$(bindir)" > $(DESTDIR)/etc/paths.d/pivy
	$(INSTALLBIN) -d $(DESTDIR)$(prefix)/share
	$(INSTALL) -o $(binowner) -g $(bingroup) -m 0644 macosx/net.cooperi.pivy-agent.plist \
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

deb:
	git archive --prefix pivy-$(VERSION)/ -o ../pivy_$(VERSION).orig.tar.gz HEAD
	DEB_BUILD_OPTIONS="parallel=4" debuild -us -uc
endif

ifeq ($(SYSTEM), OpenBSD)
install: install_common
endif

ifeq ($(HAVE_CTF), yes)
install: .ctfconvert

.ctfconvert: .ctfconvert.base
	touch $@

.ctfconvert.base: pivy-tool pivy-agent pivy-box
	$(CTFCONVERT) $(CTFOPTS) pivy-tool && \
	$(CTFCONVERT) $(CTFOPTS) pivy-agent && \
	$(CTFCONVERT) $(CTFOPTS) pivy-box && \
	touch $@

endif

ifeq ($(SYSTEM), SunOS)
_SMF_BITS=	fs-pivy \
		svc-pivy-agent \
		pivy-agent.xml \
		pivy-fs.xml
SMF_BITS=$(_SMF_BITS:%=illumos/%)

illumos/%: illumos/%.in
	sed -e 's!@@prefix@@!$(prefix)!' -e 's!@@METHODPATH@@!$(SMF_METHODS)!' < $< > $@
all: $(SMF_BITS)

install: install_common $(SMF_BITS)
	$(INSTALLBIN) -d $(DESTDIR)$(SMF_METHODS)
	$(INSTALLBIN) -d $(DESTDIR)$(SMF_MANIFESTS)
	$(INSTALLBIN) -d $(DESTDIR)$(SMF_MANIFESTS)/system
	$(INSTALLBIN) -m 0444 illumos/pivy-agent.xml $(DESTDIR)$(SMF_MANIFESTS)/system
	$(INSTALLBIN) -m 0444 illumos/pivy-fs.xml $(DESTDIR)$(SMF_MANIFESTS)/system
	$(INSTALLBIN) illumos/fs-pivy $(DESTDIR)$(SMF_METHODS)
	$(INSTALLBIN) illumos/svc-pivy-agent $(DESTDIR)$(SMF_METHODS)
endif
