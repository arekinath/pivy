/*
 * Newly written portions Copyright 2018 Joyent, Inc.
 * Author: Alex Wilson <alex.wilson@joyent.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Partially derived from the original OpenSSH agent.c.
 *
 * Original copyright and license from OpenSSH:
 *
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/mman.h>

#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "libssh/ssh2.h"
#include "libssh/sshbuf.h"
#include "libssh/sshkey.h"
#include "libssh/authfd.h"

#include "bunyan.h"
#include "debug.h"
#include "tlv.h"
#include "piv.h"

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#if defined(__sun)
#include <ucred.h>
#endif

#include "libssh/digest.h"
#include "libssh/cipher.h"
#include "libssh/ssherr.h"

#define	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

/*
 * Name of the environment variable containing the process ID of the
 * authentication agent.
 */
#define SSH_AGENTPID_ENV_NAME	"SSH_AGENT_PID"

/*
 * Name of the environment variable containing the pathname of the
 * authentication socket.
 */
#define SSH_AUTHSOCKET_ENV_NAME "SSH_AUTH_SOCK"

/* Listen backlog for sshd, ssh-agent and forwarding sockets */
#define SSH_LISTEN_BACKLOG		128

#define	MAX_PIN_LEN	16

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
static boolean_t txnopen = B_FALSE;
static uint64_t txntimeout = 0;
static SCARDCONTEXT ctx;
static uint64_t last_update;
static uint64_t last_op;
static uint8_t *guid = NULL;
static size_t guid_len = 0;

static char *pinmem = NULL;
static char *pin = NULL;
static size_t pin_len = 0;

static struct sshkey *cak = NULL;

/* Maximum accepted message length */
#define AGENT_MAX_LEN	(256*1024)

typedef enum {
	AUTH_UNUSED,
	AUTH_SOCKET,
	AUTH_CONNECTION
} sock_type;

typedef struct {
	int fd;
	sock_type type;
	struct sshbuf *input;
	struct sshbuf *output;
	struct sshbuf *request;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = NULL;

int max_fd = 0;

time_t card_probe_interval = 120;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX + 20];
char socket_dir[PATH_MAX];


/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
int locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

extern char *__progname;

/* Default lifetime in seconds (0 == forever) */
//static long lifetime = 0;

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

extern void bunyan_timestamp(char *, size_t);
static int ssh_dbglevel = WARN;
static void
sdebug(const char *fmt, ...)
{
	va_list args;
	char ts[128];
	if (ssh_dbglevel > TRACE)
		return;
	bunyan_timestamp(ts, sizeof (ts));
	va_start(args, fmt);
	fprintf(stderr, "[%s] TRACE: ", ts);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}
static void
verbose(const char *fmt, ...)
{
	va_list args;
	char ts[128];
	if (ssh_dbglevel > DEBUG)
		return;
	bunyan_timestamp(ts, sizeof (ts));
	va_start(args, fmt);
	fprintf(stderr, "[%s] DEBUG: ", ts);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}
static void
error(const char *fmt, ...)
{
	va_list args;
	char ts[128];
	if (ssh_dbglevel > ERROR)
		return;
	bunyan_timestamp(ts, sizeof (ts));
	va_start(args, fmt);
	fprintf(stderr, "[%s] ERROR: ", ts);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}
static void
fatal(const char *fmt, ...)
{
	va_list args;
	char ts[128];
	va_start(args, fmt);
	bunyan_timestamp(ts, sizeof (ts));
	fprintf(stderr, "[%s] FATAL: ", ts);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(1);
}

static uint64_t
monotime(void)
{
	struct timeval tv;
	uint64_t msec;
	gettimeofday(&tv, NULL);
	msec = tv.tv_sec * 1000;
	msec += tv.tv_usec / 1000;
	return (msec);
}

static void
agent_piv_close(boolean_t force)
{
	uint64_t now = monotime();
	VERIFY(txnopen);
	if (force || now >= txntimeout) {
		bunyan_log(TRACE, "closing txn",
		    "now", BNY_UINT64, now,
		    "txntimeout", BNY_UINT64, txntimeout, NULL);
		piv_txn_end(selk);
		txnopen = B_FALSE;
	}
}

static void
drop_pin(void)
{
	if (pin_len != 0)
		explicit_bzero(pin, pin_len);
	pin_len = 0;
}

static boolean_t
auth_cak(void)
{
	struct piv_slot *slot;
	int rc;
	slot = piv_get_slot(selk, PIV_SLOT_CARD_AUTH);
	if (slot == NULL) {
		bunyan_log(WARN, "CAK failed auth", NULL);
		return (B_FALSE);
	}
	rc = piv_auth_key(selk, slot, cak);
	if (rc != 0) {
		bunyan_log(WARN, "CAK failed auth", NULL);
		return (B_FALSE);
	}
	return (B_TRUE);
}

static int
agent_piv_open(void)
{
	struct piv_token *t;
	struct piv_slot *slot;
	int rc;

	if (txnopen) {
		txntimeout = monotime() + 2000;
		return (0);
	}

	if (selk == NULL || (rc = piv_txn_begin(selk)) != 0) {
		selk = NULL;
		if (ks != NULL)
			piv_release(ks);
		ks = piv_enumerate(ctx);

		for (t = ks; t != NULL; t = t->pt_next) {
			if (bcmp(t->pt_guid, guid, guid_len) == 0) {
				if (selk == NULL) {
					selk = t;
				} else {
					bunyan_log(ERROR, "GUID prefix is not "
					    "unique; refusing to open token",
					    NULL);
					selk = NULL;
					break;
				}
			}
		}
		if (selk == NULL) {
			bunyan_log(WARN, "PIV card with given GUID is not "
			    "present on the system", NULL);
			if (monotime() - last_update > 5000)
				drop_pin();
			return (ENOENT);
		}

		if ((rc = piv_txn_begin(selk)) != 0) {
			bunyan_log(WARN, "PIV card could not be opened",
			    "piv_txn_begin_rc", BNY_INT, rc, NULL);
			return (rc);
		}

		if ((rc = piv_select(selk)) != 0) {
			piv_txn_end(selk);
			return (rc);
		}

		rc = piv_read_all_certs(selk);
		if (rc != 0 && rc != ENOENT && rc != ENOTSUP) {
			bunyan_log(WARN, "piv_read_all_certs returned error",
			    "code", BNY_INT, rc,
			    "error", BNY_STRING, strerror(rc), NULL);
			piv_txn_end(selk);
			return (rc);
		}
		if (cak != NULL && !auth_cak()) {
			piv_txn_end(selk);
			drop_pin();
			return (ENOENT);
		}
		last_update = monotime();

	} else {
		if ((rc = piv_select(selk)) != 0) {
			piv_txn_end(selk);
			return (rc);
		}
	}
	if (cak == NULL) {
		slot = piv_get_slot(selk, PIV_SLOT_CARD_AUTH);
		if (slot != NULL)
			VERIFY0(sshkey_demote(slot->ps_pubkey, &cak));
	}
	bunyan_log(TRACE, "opened new txn", NULL);
	txnopen = B_TRUE;
	txntimeout = monotime() + 2000;
	return (0);
}

static void
probe_card(void)
{
	bunyan_log(TRACE, "doing idle probe", NULL);

	last_op = monotime();
	if (agent_piv_open() != 0) {
		goto nope;
	}
	if (cak != NULL && !auth_cak()) {
		agent_piv_close(B_TRUE);
		goto nope;
	}
	agent_piv_close(B_FALSE);
	return;

nope:
	drop_pin();
	selk = NULL;
}

static int
agent_piv_try_pin(void)
{
	int r;
	uint retries = 1;
	if (pin_len != 0) {
		r = piv_verify_pin(selk, pin, &retries);
		if (r == EACCES) {
			if (retries == 0) {
				bunyan_log(ERROR, "token is locked due to "
				    "too many invalid PIN code attempts",
				    NULL);
			} else {
				bunyan_log(ERROR, "invalid PIN code",
				    "attempts_remaining", BNY_INT, retries,
				    NULL);
				drop_pin();
			}
			return (EACCES);
		} else if (r == EAGAIN) {
			bunyan_log(ERROR, "insufficient PIN retries "
			    "remaining (stubbornly refusing to use up the "
			    "last one)", "attempts_remaining", BNY_INT, retries,
			    NULL);
			drop_pin();
			return (EACCES);
		} else if (r != 0) {
			bunyan_log(ERROR, "piv_verify_pin returned error",
			    "code", BNY_INT, r,
			    "error", BNY_STRING, strerror(r), NULL);
			return (r);
		}
	}

	return (0);
}

static void
close_socket(SocketEntry *e)
{
	close(e->fd);
	e->fd = -1;
	e->type = AUTH_UNUSED;
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
}

static int
set_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL);
	if (val < 0) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		return (-1);
	}
	if (val & O_NONBLOCK) {
		sdebug("fd %d is O_NONBLOCK", fd);
		return (0);
	}
	sdebug("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1) {
		sdebug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

static void
sanitise_stdfd(void)
{
	int nullfd, dupfd;

	if ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	while (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		if (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			if (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	if (nullfd > STDERR_FILENO)
		close(nullfd);
}

static void
send_status(SocketEntry *e, int success)
{
	int r;

	if ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

static void
send_extfail(SocketEntry *e)
{
	int r;

	if ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, SSH2_AGENT_EXT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

/* send list of supported public keys to 'client' */
static void
process_request_identities(SocketEntry *e)
{
	struct sshbuf *msg;
	struct piv_slot *slot;
	char comment[256];
	uint64_t now;
	int r, n, i;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if (agent_piv_open() != 0) {
		sshbuf_free(msg);
		send_status(e, 0);
		return;
	}
	now = monotime();
	if ((now - last_update) >= card_probe_interval * 1000) {
		last_update = now;
		piv_read_all_certs(selk);
		if (cak != NULL && !auth_cak()) {
			agent_piv_close(B_TRUE);
			drop_pin();
			sshbuf_free(msg);
			send_status(e, 0);
			return;
		}
	}
	agent_piv_close(B_FALSE);

	n = 0;
	for (i = 0x9A; i < 0x9F; ++i) {
		slot = piv_get_slot(selk, i);
		if (slot != NULL) {
			++n;
		}
	}

	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	for (i = 0x9A; i < 0x9F; ++i) {
		slot = piv_get_slot(selk, i);
		if (slot == NULL)
			continue;
		comment[0] = 0;
		snprintf(comment, sizeof (comment), "PIV_slot_%02X %s",
		    i, slot->ps_subj);
		if ((r = sshkey_puts(slot->ps_pubkey, msg)) != 0 ||
		    (r = sshbuf_put_cstring(msg, comment)) != 0) {
			error("%s: put key/comment: %s", __func__,
			    ssh_err(r));
			continue;
		}
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}

/* ssh2 only */
static void
process_sign_request2(SocketEntry *e)
{
	const u_char *data;
	u_char *signature = NULL;
	u_char *rawsig = NULL;
	size_t dlen, rslen = 0, slen = 0;
	u_int flags;
	int r, ok = -1;
	struct sshbuf *msg;
	struct sshbuf *buf;
	struct sshkey *key = NULL;
	struct piv_slot *slot;
	int found = 0;
	int i;
	enum sshdigest_types hashalg, ohashalg;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(e->request, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}

	if (agent_piv_open() != 0)
		goto send;

	for (i = 0x9A; i < 0x9F; ++i) {
		slot = piv_get_slot(selk, i);
		if (slot == NULL)
			continue;
		if (sshkey_equal(slot->ps_pubkey, key)) {
			found = 1;
			break;
		}
	}
	if (!found || slot == NULL) {
		agent_piv_close(B_FALSE);
		verbose("%s: %s key not found", __func__, sshkey_type(key));
		goto send;
	}

	if (agent_piv_try_pin() != 0) {
		agent_piv_close(B_TRUE);
		goto send;
	}
	if (key->type == KEY_RSA) {
		hashalg = SSH_DIGEST_SHA1;
		if (flags & SSH_AGENT_RSA_SHA2_256)
			hashalg = SSH_DIGEST_SHA256;
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			hashalg = SSH_DIGEST_SHA512;
	} else if (key->type == KEY_ECDSA) {
		hashalg = SSH_DIGEST_SHA256;
	}
	ohashalg = hashalg;
	r = piv_sign(selk, slot, data, dlen, &hashalg, &rawsig, &rslen);

	if (r == EPERM) {
		agent_piv_close(B_TRUE);
		fprintf(stderr, "error: no PIN has been supplied to "
		    "the agent (try ssh-add -X)\n");
		goto send;
	} else if (r != 0) {
		agent_piv_close(B_TRUE);
		fprintf(stderr, "error: PIV signing failed");
		goto send;
	}
	agent_piv_close(B_FALSE);

	if (hashalg != ohashalg) {
		fprintf(stderr, "error: PIV signed with different hash algo\n");
		goto send;
	}

	buf = sshbuf_new();
	VERIFY(buf != NULL);
	VERIFY0(sshkey_sig_from_asn1(slot->ps_pubkey, hashalg,
	    rawsig, rslen, buf));
	explicit_bzero(rawsig, rslen);
	free(rawsig);

	signature = calloc(1, sshbuf_len(buf));
	slen = sshbuf_len(buf);
	VERIFY0(sshbuf_get(buf, signature, slen));
	sshbuf_free(buf);

	/* Success */
	ok = 0;
 send:
	sshkey_free(key);
	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
	explicit_bzero(signature, slen);
	free(signature);
}

static int
valid_pin(const char *pin)
{
	int i;
	if (strlen(pin) < 6 || strlen(pin) > 8) {
		bunyan_log(WARN, "invalid PIN: must be 6-8 digits",
		     "length", BNY_UINT, (uint)strlen(pin), NULL);
		return (0);
	}
	for (i = 0; pin[i] != 0; ++i) {
		if (!(pin[i] >= '0' && pin[i] <= '9') &&
		    !(pin[i] >= 'a' && pin[i] <= 'z') &&
		    !(pin[i] >= 'A' && pin[i] <= 'Z')) {
			char val[2] = {pin[i], '\0'};

			bunyan_log(WARN, "invalid PIN: contains invalid "
			    "characters", "inval_char", BNY_STRING, val, NULL);
			return (0);
		}
	}
	return (1);
}

static void
process_remove_all_identities(SocketEntry *e)
{
	drop_pin();
	send_status(e, 1);
}

struct exthandler {
	const char *eh_name;
	void (*eh_handler)(SocketEntry *, struct sshbuf *);
};
struct exthandler exthandlers[];

static void
process_ext_ecdh(SocketEntry *e, struct sshbuf *buf)
{
	int r, i;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct sshkey *partner = NULL;
	struct piv_slot *slot;
	uint8_t *secret;
	size_t seclen;
	uint flags;
	int found = 0;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(buf, &key)) != 0 ||
	    (r = sshkey_froms(buf, &partner)) != 0 ||
	    (r = sshbuf_get_u32(buf, &flags)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto fail;
	}

	if (flags != 0)
		goto fail;

	if (agent_piv_open() != 0)
		goto fail;

	for (i = 0x9A; i < 0x9F; ++i) {
		slot = piv_get_slot(selk, i);
		if (slot == NULL)
			continue;
		if (sshkey_equal(slot->ps_pubkey, key)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		agent_piv_close(B_FALSE);
		verbose("%s: %s key not found", __func__, sshkey_type(key));
		goto fail;
	}

	if (key->type != KEY_ECDSA || partner->type != KEY_ECDSA) {
		agent_piv_close(B_FALSE);
		verbose("%s: keys are not both EC keys (%s and %s)", __func__,
		    sshkey_type(key), sshkey_type(partner));
		goto fail;
	}

	if (agent_piv_try_pin() != 0) {
		agent_piv_close(B_TRUE);
		goto fail;
	}
	r = piv_ecdh(selk, slot, partner, &secret, &seclen);\
	if (r != 0) {
		agent_piv_close(B_TRUE);
		bunyan_log(ERROR, "piv_ecdh returned error",
		    "code", BNY_INT, r,
		    "error", BNY_STRING, strerror(r), NULL);
		goto fail;
	}
	agent_piv_close(B_FALSE);

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_string(msg, secret, seclen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	explicit_bzero(secret, seclen);
	free(secret);

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	goto done;

fail:
	send_extfail(e);

done:
	sshbuf_free(msg);
	sshkey_free(key);
	sshkey_free(partner);
}

static void
process_ext_rebox(SocketEntry *e, struct sshbuf *buf)
{
	int r;
	struct sshbuf *msg, *boxbuf, *guid;
	struct sshkey *partner;
	struct piv_ecdh_box *box = NULL, *newbox = NULL;
	uint8_t slotid;
	uint flags;
	struct piv_slot *slot;
	struct piv_token *tk;
	uint8_t *secret = NULL, *out = NULL;
	size_t seclen, outlen;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_froms(buf, &boxbuf)) != 0 ||
	    (r = sshbuf_froms(buf, &guid)) != 0 ||
	    (r = sshbuf_get_u8(buf, &slotid)) != 0 ||
	    (r = sshkey_froms(buf, &partner)) != 0 ||
	    (r = sshbuf_get_u32(buf, &flags)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto fail;
	}

	if (flags != 0)
		goto fail;

	r = piv_box_from_binary(sshbuf_ptr(boxbuf), sshbuf_len(boxbuf), &box);
	if (r != 0)
		goto fail;

	r = piv_box_find_token(selk, box, &tk, &slot);
	if (r != 0)
		goto fail;
	if (tk != selk)
		goto fail;

	if (agent_piv_open() != 0)
		goto fail;
	if (agent_piv_try_pin() != 0) {
		agent_piv_close(B_TRUE);
		goto fail;
	}
	if ((r = piv_box_open(selk, slot, box)) != 0 ||
	    (r = piv_box_take_data(box, &secret, &seclen)) != 0) {
		agent_piv_close(B_TRUE);
		goto fail;
	}
	agent_piv_close(B_FALSE);

	newbox = piv_box_new();
	VERIFY(newbox != NULL);

	bcopy(sshbuf_ptr(guid), newbox->pdb_guid, sizeof (newbox->pdb_guid));
	newbox->pdb_slot = slotid;
	VERIFY0(piv_box_set_data(newbox, secret, seclen));
	if ((r = piv_box_seal_offline(partner, newbox)) != 0)
		goto fail;

	VERIFY0(piv_box_to_binary(newbox, &out, &outlen));

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_string(msg, out, outlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	goto done;

fail:
	send_extfail(e);
done:
	if (box != NULL)
		piv_box_free(box);
	if (newbox != NULL)
		piv_box_free(newbox);
	if (secret != NULL) {
		explicit_bzero(secret, seclen);
		free(secret);
	}
	if (out != NULL) {
		explicit_bzero(out, outlen);
		free(out);
	}
	sshbuf_free(msg);
	sshkey_free(partner);
	sshbuf_free(boxbuf);
	sshbuf_free(guid);
}

static void
process_ext_x509_certs(SocketEntry *e, struct sshbuf *buf)
{
	/*int r;
	struct sshbuf *msg;*/
	send_extfail(e);
}

static void
process_ext_query(SocketEntry *e, struct sshbuf *buf)
{
	int r, n = 0;
	struct exthandler *h;
	struct sshbuf *msg;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	for (h = exthandlers; h->eh_name != NULL; ++h)
		++n;

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	for (h = exthandlers; h->eh_name != NULL; ++h) {
		if ((r = sshbuf_put_cstring(msg, h->eh_name)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}

struct exthandler exthandlers[] = {
	{ "query", process_ext_query },
	{ "ecdh@joyent.com", process_ext_ecdh },
	{ "ecdh-rebox@joyent.com", process_ext_rebox },
	{ "x509-certs@joyent.com", process_ext_x509_certs },
	{ NULL, NULL }
};

static void
process_extension(SocketEntry *e)
{
	int r;
	char *extname;
	size_t enlen;
	struct sshbuf *inner;
	struct exthandler *h, *hdlr = NULL;

	if ((r = sshbuf_get_cstring(e->request, &extname, &enlen)) != 0 ||
	    (r = sshbuf_froms(e->request, &inner)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	VERIFY(extname != NULL);
	VERIFY(inner != NULL);

	for (h = exthandlers; h->eh_name != NULL; ++h) {
		if (strcmp(h->eh_name, extname) == 0) {
			hdlr = h;
			break;
		}
	}
	if (hdlr == NULL) {
		send_status(e, 0);
		return;
	}
	hdlr->eh_handler(e, inner);

	sshbuf_free(inner);
}

static void
process_lock_agent(SocketEntry *e, int lock)
{
	int r, ret = 0;
	char *passwd;
	size_t pwlen;
	uint retries = 1;

	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	VERIFY(passwd != NULL);

	if (lock) {
		drop_pin();
		explicit_bzero(passwd, pwlen);
		free(passwd);
		ret = 1;
	} else {
		if (!valid_pin(passwd)) {
			goto out;
		}

		if (agent_piv_open() != 0) {
			goto out;
		}
		r = piv_verify_pin(selk, passwd, &retries);

		if (r == 0) {
			agent_piv_close(B_FALSE);
			if (pin_len != 0)
				explicit_bzero(pin, pin_len);
			pin_len = pwlen;
			bcopy(passwd, pin, pwlen + 1);
			ret = 1;
			goto out;
		}
		agent_piv_close(B_TRUE);

		if (r == EACCES) {
			if (retries == 0) {
				bunyan_log(ERROR, "token is locked due to "
				    "too many invalid PIN retries", NULL);
			} else {
				bunyan_log(ERROR, "invalid PIN code",
				    "attempts_left", BNY_INT, retries, NULL);
			}
		} else if (r == EAGAIN) {
			bunyan_log(ERROR, "insufficient retries remaining; "
			    "didn't attempt PIN to avoid locking card",
			    "attempts_left", BNY_INT, retries, NULL);
		}
		bunyan_log(ERROR, "piv_verify_pin returned error",
		    "code", BNY_INT, r, "error", BNY_STRING, strerror(r), NULL);
	}
out:
	explicit_bzero(passwd, pwlen);
	free(passwd);
	send_status(e, ret);
}

/* dispatch incoming messages */

static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	SocketEntry *e;

	if (socknum >= sockets_alloc) {
		fatal("%s: socket number %u >= allocated %u",
		    __func__, socknum, sockets_alloc);
	}
	e = &sockets[socknum];

	if (sshbuf_len(e->input) < 5)
		return 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		sdebug("%s: socket %u (fd=%d) message too long %u > %u",
		    __func__, socknum, e->fd, msg_len, AGENT_MAX_LEN);
		return -1;
	}
	if (sshbuf_len(e->input) < msg_len + 4)
		return 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	if ((r = sshbuf_get_stringb(e->input, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		if (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			sdebug("%s: buffer error: %s", __func__, ssh_err(r));
			return -1;
		}
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	sdebug("%s: socket %u (fd=%d) type %d", __func__, socknum, e->fd, type);

	last_op = monotime();

	switch (type) {
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		break;
	/* ssh2 */
	case SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		break;
	case SSH2_AGENTC_EXTENSION:
		process_extension(e);
		break;
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 0;
}

extern void *reallocarray(void *ptr, size_t nmemb, size_t size);

static void
new_socket(sock_type type, int fd)
{
	u_int i, old_alloc, new_alloc;

	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			if ((sockets[i].input = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].output = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].request = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			sockets[i].type = type;
			return;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = reallocarray(sockets, new_alloc, sizeof(SocketEntry));
	VERIFY(sockets != NULL);
	for (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	if ((sockets[old_alloc].input = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].output = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].request = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	sockets[old_alloc].type = type;
}

static int
handle_socket_read(u_int socknum)
{
	struct sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	int fd;
#if defined(__sun)
	ucred_t *peer;
#endif

	slen = sizeof(sunaddr);
	fd = accept(sockets[socknum].fd, (struct sockaddr *)&sunaddr, &slen);
	if (fd < 0) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		return -1;
	}
#if defined(__sun)
	if (getpeerucred(fd, &peer) != 0) {
		error("getpeerucred %d failed: %s", fd, strerror(errno));
		close(fd);
		return -1;
	}
	euid = ucred_geteuid(peer);
	egid = ucred_getegid(peer);
	ucred_free(peer);
#else
	if (getpeereid(fd, &euid, &egid) < 0) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		return -1;
	}
#endif
	if ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		return -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	return 0;
}

static int
handle_conn_read(u_int socknum)
{
	char buf[1024];
	ssize_t len;
	int r;

	if ((len = read(sockets[socknum].fd, buf, sizeof(buf))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	explicit_bzero(buf, sizeof(buf));
	process_message(socknum);
	return 0;
}

static int
handle_conn_write(u_int socknum)
{
	ssize_t len;
	int r;

	if (sshbuf_len(sockets[socknum].output) == 0)
		return 0; /* shouldn't happen */
	if ((len = write(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	return 0;
}

static void
after_poll(struct pollfd *pfd, size_t npfd)
{
	size_t i;
	u_int socknum;

	for (i = 0; i < npfd; i++) {
		if (pfd[i].revents == 0)
			continue;
		/* Find sockets entry */
		for (socknum = 0; socknum < sockets_alloc; socknum++) {
			if (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				continue;
			if (pfd[i].fd == sockets[socknum].fd)
				break;
		}
		if (socknum >= sockets_alloc) {
			error("%s: no socket for fd %d", __func__, pfd[i].fd);
			continue;
		}
		/* Process events */
		switch (sockets[socknum].type) {
		case AUTH_SOCKET:
			if ((pfd[i].revents & (POLLIN|POLLERR)) != 0 &&
			    handle_socket_read(socknum) != 0)
				close_socket(&sockets[socknum]);
			break;
		case AUTH_CONNECTION:
			if ((pfd[i].revents & (POLLIN|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0) {
				close_socket(&sockets[socknum]);
				break;
			}
			if ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0)
				close_socket(&sockets[socknum]);
			break;
		default:
			break;
		}
	}
}

static int
prepare_poll(struct pollfd **pfdp, size_t *npfdp, int *timeoutp)
{
	struct pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	uint64_t now, deadline;

	/* Count active sockets */
	for (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			npfd++;
			break;
		case AUTH_UNUSED:
			break;
		default:
			fatal("Unknown socket type %d", sockets[i].type);
			break;
		}
	}
	if (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, sizeof(struct pollfd))) == NULL)
		fatal("%s: recallocarray failed", __func__);
	*pfdp = pfd;
	*npfdp = npfd;

	for (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/* XXX backoff when input buffer full */
			pfd[j].events = POLLIN;
			if (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			break;
		default:
			break;
		}
	}
	now = monotime();
	deadline = txnopen ? (txntimeout - now) : 0;
	if (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval * 1000 :
		    MINIMUM(deadline, parent_alive_interval * 1000);
	if (card_probe_interval != 0)
		deadline = (deadline == 0) ? card_probe_interval * 1000 :
		    MINIMUM(deadline, card_probe_interval * 1000);
	if (deadline == 0) {
		*timeoutp = -1; /* INFTIM */
	} else {
		if (deadline > INT_MAX)
			*timeoutp = INT_MAX;
		else
			*timeoutp = deadline;
	}
	return (1);
}

static void
cleanup_socket(void)
{
	if (cleanup_pid != 0 && getpid() != cleanup_pid)
		return;
	sdebug("%s: cleanup", __func__);
	if (socket_name[0])
		unlink(socket_name);
	if (socket_dir[0])
		rmdir(socket_dir);
}

void
cleanup_exit(int i)
{
	cleanup_socket();
	_exit(i);
}

/*ARGSUSED*/
static void
cleanup_handler(int sig)
{
	cleanup_socket();
	_exit(2);
}

static void
check_parent_exists(void)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	if (parent_pid != -1 && getppid() != parent_pid) {
		bunyan_log(INFO, "Parent has died - Authentication agent exiting.");
		cleanup_socket();
		_exit(2);
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: piv-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n"
	    "                 [-t life] [-g guid] [-K cak] [command [arg ...]]\n"
	    "       piv-agent [-c | -s] -k\n");
	exit(1);
}

static uint8_t *
parse_hex(const char *str, uint *outlen)
{
	const uint len = strlen(str);
	uint8_t *data = calloc(1, len / 2 + 1);
	uint idx = 0;
	uint shift = 4;
	uint i;
	for (i = 0; i < len; ++i) {
		const char c = str[i];
		int skip = 0;
		if (c >= '0' && c <= '9') {
			data[idx] |= (c - '0') << shift;
		} else if (c >= 'a' && c <= 'f') {
			data[idx] |= (c - 'a' + 0xa) << shift;
		} else if (c >= 'A' && c <= 'F') {
			data[idx] |= (c - 'A' + 0xA) << shift;
		} else if (c == ':' || c == ' ' || c == '\t' ||
		    c == '\n' || c == '\r') {
			skip = 1;
		} else {
			fprintf(stderr, "error: invalid hex digit: '%c'\n", c);
			exit(1);
		}
		if (skip == 0) {
			if (shift == 4) {
				shift = 0;
			} else if (shift == 0) {
				++idx;
				shift = 4;
			}
		}
	}
	if (shift == 0) {
		fprintf(stderr, "error: odd number of hex digits "
		    "(incomplete)\n");
		exit(1);
	}
	*outlen = idx;
	return (data);
}

static int
unix_listener(const char *path, int backlog, int unlink_first)
{
	struct sockaddr_un sunaddr;
	int saved_errno, sock;

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	if (strlcpy(sunaddr.sun_path, path,
	    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
		error("%s: path \"%s\" too long for Unix domain socket",
		    __func__, path);
		errno = ENAMETOOLONG;
		return -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		saved_errno = errno;
		error("%s: socket: %.100s", __func__, strerror(errno));
		errno = saved_errno;
		return -1;
	}
	if (unlink_first == 1) {
		if (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
		saved_errno = errno;
		error("%s: cannot bind to path %s: %s",
		    __func__, path, strerror(errno));
		close(sock);
		errno = saved_errno;
		return -1;
	}
	if (listen(sock, backlog) < 0) {
		saved_errno = errno;
		error("%s: cannot listen on path %s: %s",
		    __func__, path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		return -1;
	}
	return sock;
}

/* Make a template filename for mk[sd]temp() */
static void
mktemp_proto(char *s, size_t len)
{
	const char *tmpdir;
	int r;

	if ((tmpdir = getenv("TMPDIR")) != NULL) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		if (r > 0 && (size_t)r < len)
			return;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	if (r < 0 || (size_t)r >= len)
		fatal("%s: template string too short", __func__);
}

#if defined(__APPLE__)
#define INVALID 	1
#define TOOSMALL 	2
#define TOOLARGE 	3

static long long
strtonum(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
	long long ll = 0;
	char *ep;
	int error = 0;
	struct errval {
		const char *errstr;
		int err;
	} ev[4] = {
		{ NULL,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	if (minval > maxval)
		error = INVALID;
	else {
		ll = strtoll(numstr, &ep, 10);
		if (numstr == ep || *ep != '\0')
			error = INVALID;
		else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	if (errstrp != NULL)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	if (error)
		ll = 0;

	return (ll);
}
#endif

int
main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int sock, fd, ch, result, saved_errno;
	char *shell, *format, *pidstr, *agentsocket = NULL;
	extern int optind;
	extern char *optarg;
	pid_t pid;
	char pidstrbuf[1 + 3 * sizeof pid];
	uint len = 0;
	mode_t prev_mask;
	int timeout = -1; /* INFTIM */
	struct pollfd *pfd = NULL;
	size_t npfd = 0;
	uint64_t now;
	char *ptr;
	int r;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	VERIFY0(setegid(getgid()));
	VERIFY0(setgid(getgid()));

	OpenSSL_add_all_algorithms();

	bunyan_init();
	bunyan_set_name("piv-agent");

	__progname = "piv-agent";

	while ((ch = getopt(ac, av, "cDdksE:a:P:g:K:")) != -1) {
		switch (ch) {
		case 'g':
			guid = parse_hex(optarg, &len);
			guid_len = len;
			if (len > 16) {
				fprintf(stderr, "error: GUID must be <=16 bytes"
				    " in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'K':
			cak = sshkey_new(KEY_UNSPEC);
			VERIFY(cak != NULL);
			ptr = optarg;
			r = sshkey_read(cak, &ptr);
			if (r != 0)
				fatal("Invalid CAK key given: %ld", r);
			break;
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'c':
			if (s_flag)
				usage();
			c_flag++;
			break;
		case 'k':
			k_flag++;
			break;
		case 'P':
			fatal("pkcs11 options not supported");
			break;
		case 's':
			if (c_flag)
				usage();
			s_flag++;
			break;
		case 'd':
			if (d_flag || D_flag)
				usage();
			d_flag++;
			break;
		case 'D':
			if (d_flag || D_flag)
				usage();
			D_flag++;
			break;
		case 'a':
			agentsocket = optarg;
			break;
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	if (ac > 0 && (c_flag || k_flag || s_flag || d_flag || D_flag))
		usage();

	if (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		if (shell != NULL && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	if (guid == NULL)
		usage();
	if (k_flag) {
		const char *errstr = NULL;

		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		if (pidstr == NULL) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (int)strtonum(pidstr, 2, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		if (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	parent_pid = getpid();

	if (agentsocket == NULL) {
		/* Create private directory for agent socket */
		mktemp_proto(socket_dir, sizeof(socket_dir));
		if (mkdtemp(socket_dir) == NULL) {
			perror("mkdtemp: private socket dir");
			exit(1);
		}
		snprintf(socket_name, sizeof socket_name, "%s/agent.%ld", socket_dir,
		    (long)parent_pid);
	} else {
		/* Try to use specified agent socket */
		socket_dir[0] = '\0';
		strlcpy(socket_name, agentsocket, sizeof socket_name);
	}

	prev_mask = umask(0177);
	sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
	if (sock < 0) {
		/* XXX - unix_listener() calls error() not perror() */
		*socket_name = '\0'; /* Don't unlink any existing file */
		cleanup_exit(1);
	}
	umask(prev_mask);

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	if (D_flag || d_flag) {
		ssh_dbglevel = TRACE;
		bunyan_set_level(TRACE);
		format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
		    SSH_AUTHSOCKET_ENV_NAME);
		printf("echo Agent pid %ld;\n", (long)parent_pid);
		fflush(stdout);
		goto skip;
	}
#if defined(__APPLE__)
	ssh_dbglevel = INFO;
	bunyan_set_level(INFO);
	if (ac != 0) {
		bunyan_log(FATAL, "OSX does not support fork() inside "
		    "applications which use smartcards, and you have "
		    "specified a command to run. It is not possible to "
		    "execute it and remain in the foreground", NULL);
		exit(1);
	}
	bunyan_log(WARN, "OSX does not support fork() inside applications "
	    "which use smartcards; this agent will operate in the foreground",
	    NULL);
	format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
	printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
	    SSH_AUTHSOCKET_ENV_NAME);
	printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
	    SSH_AGENTPID_ENV_NAME);
	printf("echo Agent pid %ld;\n", (long)parent_pid);
	fflush(stdout);

#else
	pid = fork();
	if (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	if (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, sizeof pidstrbuf, "%ld", (long)pid);
		if (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		if (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	ssh_dbglevel = INFO;
	bunyan_set_level(INFO);

	if (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	VERIFY0(chdir("/"));
	if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		/* XXX might close listen socket */
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		//(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			close(fd);
	}
#endif

skip:

	r = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (r != 0) {
		bunyan_log(WARN, "mlockall() failed, sensitive data (e.g. PIN) "
		    "may be swapped out to disk if system is low on memory",
		    "error", BNY_STRING, strerror(r), NULL);
	}

	long pgsz = sysconf(_SC_PAGESIZE);
	pinmem = mmap(NULL, 3*pgsz, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	VERIFY(pinmem != MAP_FAILED);
#if defined(MADV_DONTDUMP)
	r = madvise(pinmem, 3*pgsz, MADV_DONTDUMP);
	if (r != 0) {
		bunyan_log(WARN, "madvice(MADV_DONTDUMP) failed, sensitive "
		    "data (e.g. PIN) may be contined in core dumps",
		    "error", BNY_STRING, strerror(errno), NULL);
	}
#endif
	VERIFY0(mprotect(pinmem, pgsz, PROT_NONE));
	VERIFY0(mprotect(pinmem + 2*pgsz, pgsz, PROT_NONE));
	pin = pinmem + pgsz;
	explicit_bzero(pin, MAX_PIN_LEN);

	cleanup_pid = getpid();

	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	signal(SIGPIPE, SIG_IGN);
#if defined(__APPLE__)
	signal(SIGINT, cleanup_handler);
#else
	signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
#endif
	signal(SIGHUP, cleanup_handler);
	signal(SIGTERM, cleanup_handler);

	r = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (r != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardEstablishContext failed",
		    "error", BNY_STRING, pcsc_stringify_error(r), NULL);
		return (1);
	}

	ks = piv_enumerate(ctx);

	if (ks == NULL) {
		bunyan_log(WARN, "no PIV cards present", NULL);
	}

	r = agent_piv_open();
	if (r == 0)
		agent_piv_close(B_TRUE);
	last_op = monotime();

	while (1) {
		prepare_poll(&pfd, &npfd, &timeout);
		result = poll(pfd, npfd, timeout);
		saved_errno = errno;
		if (parent_alive_interval != 0)
			check_parent_exists();
		now = monotime();
		if (card_probe_interval != 0 &&
		    (now - last_op) >= card_probe_interval * 1000) {
			probe_card();
		}
		if (txnopen && now >= txntimeout)
			agent_piv_close(B_TRUE);
		/*(void) reaper();*/	/* remove expired keys */
		if (result < 0) {
			if (saved_errno == EINTR)
				continue;
			fatal("poll: %s", strerror(saved_errno));
		} else if (result > 0)
			after_poll(pfd, npfd);
	}
	/* NOTREACHED */
}
