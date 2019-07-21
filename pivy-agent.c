/*
 * Newly written portions Copyright 2018 Joyent, Inc.
 * Copyright 2023 The University of Queensland
 * Author: Alex Wilson <alex.wilson@joyent.com>, <alex@uq.edu.au>
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
#include <sys/wait.h>

#include "debug.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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
#include <libgen.h>
#include <pwd.h>

#include "utils.h"

#include "openssh/config.h"
#include "openssh/ssh2.h"
#include "openssh/sshbuf.h"
#include "openssh/sshkey.h"
#include "openssh/authfd.h"
#include "openssh/ssherr.h"

#include "bunyan.h"
#include "tlv.h"
#include "piv.h"
#include "errf.h"
#include "slot-spec.h"

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#if defined(__sun)
#include <ucred.h>
#include <procfs.h>
#include <zone.h>
#endif

#if defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif

#if defined(__APPLE__)
#include <sys/proc_info.h>
#include <sys/ucred.h>
#include <libproc.h>
#endif

#include "openssh/digest.h"
#include "openssh/cipher.h"
#include "openssh/ssherr.h"

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

#define	parserrf(sshfunc, rc)	\
    errf("ParseError", ssherrf(sshfunc, rc), \
    "failed to parse request in %s", __func__)
#define	nopinerrf(cause)		\
    errf("NoPINError", cause, "no PIN has been supplied to the agent " \
    "(try ssh-add -X)")
#define	flagserrf(val)		\
    errf("FlagsError", NULL, "unsupported flags value: %x", val)
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))

typedef enum confirm_mode {
	C_NEVER,
	C_CONNECTION,
	C_FORWARDED
} confirm_mode_t;

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
static boolean_t txnopen = B_FALSE;
static uint64_t txntimeout = 0;
static struct piv_ctx *ctx;
static uint64_t last_update;
static uint8_t *guid = NULL;
static size_t guid_len = 0;
static boolean_t sign_9d = B_FALSE;
static confirm_mode_t confirm_mode = C_NEVER;
static struct slotspec *slot_ena;

typedef struct uid_entry {
	struct uid_entry	*ue_next;
	uid_t			 ue_uid;
} uid_entry_t;
#define	UID_MOD		32
static uid_entry_t *uid_allow[UID_MOD] = { NULL };
static boolean_t allow_any_uid = B_FALSE;

#if defined(__sun)
typedef struct zone_entry {
	struct zone_entry	*ze_next;
	zoneid_t		 ze_zid;
} zone_entry_t;
#define ZID_MOD		32
static zone_entry_t *zone_allow[ZID_MOD] = { NULL };
static boolean_t allow_any_zoneid = B_FALSE;
#endif

static char *pinmem = NULL;
static char *pin = NULL;
static size_t pin_len = 0;

static struct sshkey *cak = NULL;

static struct bunyan_frame *msg_log_frame;

/* Maximum accepted message length */
#define AGENT_MAX_LEN	(256*1024)

typedef enum sock_type {
	AUTH_UNUSED,
	AUTH_SOCKET,
	AUTH_CONNECTION
} sock_type_t;

typedef enum authz {
	AUTHZ_NOT_YET = 0,
	AUTHZ_DENIED,
	AUTHZ_ALLOWED
} authz_t;

typedef enum sessbind {
	SESSBIND_NONE = 0,
	SESSBIND_AUTH,
	SESSBIND_FWD
} sessbind_t;

typedef struct pid_entry {
	boolean_t	pe_valid;
	uint64_t	pe_time;
	pid_t		pe_pid;
	uint64_t	pe_start_time;
	uint		pe_conn_count;
	uint64_t	pe_last_auth;
} pid_entry_t;

typedef struct socket_entry {
	int 		 se_fd;
	sock_type_t	 se_type;
	pid_t		 se_pid;
	uid_t		 se_uid;
	gid_t		 se_gid;
	char		*se_exepath;
	char		*se_exeargs;
	authz_t		 se_authz;
	struct sshbuf	*se_input;
	struct sshbuf	*se_output;
	struct sshbuf	*se_request;
	pid_entry_t	*se_pid_ent;
	uint		 se_pid_idx;
	sessbind_t	 se_sbind;
#if defined(__sun)
	zoneid_t	 se_zid;
	char		 se_zname[128];
#endif
} socket_entry_t;

u_int sockets_alloc = 0;
socket_entry_t *sockets = NULL;

pid_entry_t *pids = NULL;
uint pids_alloc = 0;

int max_fd = 0;

const time_t card_probe_interval_nopin = 120;
const time_t card_probe_interval_pin = 30;
const uint card_probe_limit = 3;

const uint64_t pid_auth_cache_time = 15000;

time_t card_probe_interval = 120; /* card_probe_interval_nopin */
uint card_probe_fails = 0;
uint64_t card_probe_next = 0;

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
static int ssh_dbglevel = BNY_WARN;
static void
sdebug(const char *fmt, ...)
{
	va_list args;
	char ts[128];
	if (ssh_dbglevel > BNY_TRACE)
		return;
	bunyan_timestamp(ts, sizeof (ts));
	va_start(args, fmt);
	fprintf(stderr, "[%s] TRACE: ", ts);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}
static void
error(const char *fmt, ...)
{
	va_list args;
	char ts[128];
	if (ssh_dbglevel > BNY_ERROR)
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

static inline boolean_t
is_slot_enabled(struct piv_slot *slot)
{
	return (slotspec_test(slot_ena, piv_slot_id(slot)));
}

static void
add_uid(uid_t uid)
{
	uid_entry_t *ue;
	uint slot = uid % UID_MOD;
	ue = calloc(1, sizeof (uid_entry_t));
	ue->ue_uid = uid;
	ue->ue_next = uid_allow[slot];
	uid_allow[slot] = ue;
}

static int
check_uid(uid_t uid)
{
	uid_entry_t *ue;
	uint slot = uid % UID_MOD;
	for (ue = uid_allow[slot]; ue != NULL; ue = ue->ue_next) {
		if (ue->ue_uid == uid)
			return (1);
	}
	return (0);
}

#if defined(__sun)
static void
add_zid(zoneid_t zid)
{
	zone_entry_t *ze;
	uint slot = zid % ZID_MOD;
	ze = calloc(1, sizeof (zone_entry_t));
	ze->ze_zid = zid;
	ze->ze_next = zone_allow[slot];
	zone_allow[slot] = ze;
}

static int
check_zid(zoneid_t zid)
{
	zone_entry_t *ze;
	uint slot = zid % ZID_MOD;
	for (ze = zone_allow[slot]; ze != NULL; ze = ze->ze_next) {
		if (ze->ze_zid == zid)
			return (1);
	}
	return (0);
}
#endif

static void
agent_piv_close(boolean_t force)
{
	uint64_t now = monotime();
	VERIFY(txnopen);
	if (force || now >= txntimeout) {
		bunyan_log(BNY_TRACE, "closing txn",
		    "now", BNY_UINT64, now,
		    "txntimeout", BNY_UINT64, txntimeout, NULL);
		piv_txn_end(selk);
		txnopen = B_FALSE;
	}
}

static char *
piv_token_shortid(struct piv_token *pk)
{
	char *guid;
	if (piv_token_has_chuid(pk)) {
		guid = strdup(piv_token_guid_hex(pk));
	} else {
		guid = strdup("0000000000");
	}
	guid[8] = '\0';
	return (guid);
}

static const char *
pin_type_to_name(enum piv_pin type)
{
	switch (type) {
	case PIV_PIN:
		return ("PIV PIN");
	case PIV_GLOBAL_PIN:
		return ("Global PIN");
	case PIV_PUK:
		return ("PUK");
	default:
		VERIFY(0);
		return (NULL);
	}
}

static errf_t *
valid_pin(const char *pin)
{
	int i;
	if (strlen(pin) < 4 || strlen(pin) > 8) {
		return (errf("InvalidPIN", NULL, "PIN must be 4-8 characters "
		    "(was given %d)", strlen(pin)));
	}
	for (i = 0; pin[i] != 0; ++i) {
		if (!(pin[i] >= '0' && pin[i] <= '9') &&
		    !(pin[i] >= 'a' && pin[i] <= 'z') &&
		    !(pin[i] >= 'A' && pin[i] <= 'Z')) {
			return (errf("InvalidPIN", NULL, "PIN contains "
			    "invalid characters: '%c'", pin[i]));
		}
	}
	return (NULL);
}

static void
set_probe_interval(boolean_t pin_loaded)
{
	uint64_t now;

	now = monotime();

	if (pin_loaded)
		card_probe_interval = card_probe_interval_pin;
	else
		card_probe_interval = card_probe_interval_nopin;

	now += card_probe_interval * 1000;
	if (now <= card_probe_next)
		card_probe_next = now;
}

static void
extend_probe_deadline(void)
{
	uint64_t now;
	now = monotime();
	now += card_probe_interval * 1000;
	card_probe_next = now;
}

static void
drop_pin(void)
{
	if (pin_len != 0) {
		bunyan_log(BNY_INFO, "clearing PIN from memory", NULL);
		explicit_bzero(pin, pin_len);
	}
	pin_len = 0;
	set_probe_interval(B_FALSE);
}

static errf_t *
auth_cak(void)
{
	struct piv_slot *slot;
	errf_t *err;
	slot = piv_get_slot(selk, PIV_SLOT_CARD_AUTH);
	if (slot == NULL) {
		err = errf("CAKAuthError", NULL, "No key was found in the "
		    "CARD_AUTH (CAK) slot");
		return (err);
	}
	err = piv_auth_key(selk, slot, cak);
	if (err) {
		err = errf("CAKAuthError", err, "Key in CARD_AUTH slot (CAK) "
		    "does not match the configured CAK: this card may be "
		    "a fake!");
		return (err);
	}
	return (NULL);
}

static errf_t *
agent_piv_open(void)
{
	struct piv_slot *slot;
	errf_t *err = NULL;

	if (txnopen) {
		txntimeout = monotime() + 2000;
		return (NULL);
	}

	if (selk == NULL || (err = piv_txn_begin(selk))) {
		errf_free(err);

		selk = NULL;
		if (ks != NULL)
			piv_release(ks);

findagain:
		err = piv_find(ctx, guid, guid_len, &ks);
		if (err && errf_caused_by(err, "PCSCContextError")) {
			ks = NULL;
			bunyan_log(BNY_TRACE, "got context error, re-initing",
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
			piv_close(ctx);
			ctx = piv_open();
			err = piv_establish_context(ctx, SCARD_SCOPE_SYSTEM);
			if (err)
				return (err);
			goto findagain;
		} else if (err) {
			ks = NULL;
			err = errf("EnumerationError", err, "Failed to "
			    "find specified PIV token on the system");
			return (err);
		}
		selk = ks;

		if (selk == NULL) {
			err = errf("NotFoundError", NULL, "PIV card with "
			    "given GUID is not present on the system");
			if (monotime() - last_update > 5000)
				drop_pin();
			return (err);
		}

		if ((err = piv_txn_begin(selk))) {
			return (err);
		}

		if ((err = piv_select(selk))) {
			piv_txn_end(selk);
			return (err);
		}

		err = piv_read_all_certs(selk);
		if (err && !errf_caused_by(err, "NotFoundError") &&
		    !errf_caused_by(err, "NotSupportedError")) {
			piv_txn_end(selk);
			return (err);
		}
		if (cak != NULL && (err = auth_cak())) {
			piv_txn_end(selk);
			drop_pin();
			return (err);
		}
		last_update = monotime();

	} else {
		if ((err = piv_select(selk))) {
			piv_txn_end(selk);
			return (err);
		}
	}
	if (cak == NULL) {
		slot = piv_get_slot(selk, PIV_SLOT_CARD_AUTH);
		if (slot != NULL)
			VERIFY0(sshkey_demote(piv_slot_pubkey(slot), &cak));
	}
	bunyan_log(BNY_TRACE, "opened new txn", NULL);
	txnopen = B_TRUE;
	txntimeout = monotime() + 2000;
	card_probe_fails = 0;
	return (NULL);
}

static void
probe_card(void)
{
	errf_t *err;
	uint64_t now;

	now = monotime();
	card_probe_next = now + card_probe_interval * 1000;

	if (card_probe_fails > card_probe_limit)
		return;

	bunyan_log(BNY_TRACE, "doing idle probe", NULL);

	if ((err = agent_piv_open())) {
		bunyan_log(BNY_TRACE, "error opening for idle probe",
		    "error", BNY_ERF, err, NULL);
		errf_free(err);
		/*
		 * Allow one failure due to connectivity issues before we
		 * drop the PIN (so that transient glitches aren't so
		 * inconvenient).
		 */
		if (card_probe_fails++ > 0)
			drop_pin();
		selk = NULL;
		card_probe_next = now + card_probe_interval * 1000;
		return;
	}
	if (cak != NULL && (err = auth_cak())) {
		bunyan_log(BNY_WARN, "CAK authentication failed",
		    "error", BNY_ERF, err, NULL);
		agent_piv_close(B_TRUE);
		/* Always drop PIN on a CAK failure. */
		drop_pin();
		selk = NULL;
		card_probe_fails++;
		card_probe_next = now + card_probe_interval * 1000;
		return;
	}
	agent_piv_close(B_FALSE);
	card_probe_fails = 0;
}

static errf_t *
wrap_pin_error(errf_t *err, int retries)
{
	if (errf_caused_by(err, "PermissionError")) {
		if (retries == 0) {
			err = errf("TokenLocked", err,
			    "PIV token is locked due to too many "
			    "invalid PIN code attempts");
		} else {
			err = errf("InvalidPIN", err,
			    "Invalid PIN code supplied (%d attempts "
			    "remaining)", retries);
			drop_pin();
		}
	} else if (errf_caused_by(err, "MinRetriesError")) {
		err = errf("TokenLocked", err,
		    "Refusing to use up the last PIN code attempt: "
		    "unlock the token with another tool to clear "
		    "the counter (e.g. pivy-tool with -f)");
		drop_pin();
	}
	return (err);
}

static const char *askpass = NULL;
static const char *confirm = NULL;
static const char *notify = NULL;

static void
try_askpass(void)
{
	int p[2], status;
	pid_t kid, ret;
	size_t len;
	errf_t *err;
	uint retries = 1;
	char prompt[64], buf[1024];
	char *guid = piv_token_shortid(selk);
	enum piv_pin auth = piv_token_default_auth(selk);
	snprintf(prompt, 64, "Enter %s for token %s",
	    pin_type_to_name(auth), guid);

	if (askpass == NULL)
		askpass = getenv("SSH_ASKPASS");
	if (askpass == NULL)
		return;

	if (pipe(p) == -1)
		return;
	if ((kid = fork()) == -1)
		return;
	if (kid == 0) {
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) == -1)
			exit(1);
		execlp(askpass, askpass, prompt, (char *)NULL);
		exit(1);
	}
	close(p[1]);

	len = 0;
	do {
		ssize_t r = read(p[0], buf + len, sizeof(buf) - 1 - len);

		if (r == -1 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		len += r;
	} while (sizeof(buf) - 1 - len > 0);
	buf[len] = '\0';

	close(p[0]);
	while ((ret = waitpid(kid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, sizeof(buf));
		bunyan_log(BNY_WARN, "executing askpass failed",
		    "exit_status", BNY_UINT, (uint)WEXITSTATUS(status),
		    NULL);
		return;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	if ((err = valid_pin(buf))) {
		errf_free(err);
		goto out;
	}
	if ((err = agent_piv_open())) {
		errf_free(err);
		goto out;
	}
	err = piv_verify_pin(selk, auth, buf, &retries, B_FALSE);
	if (err != ERRF_OK) {
		err = wrap_pin_error(err, retries);
		bunyan_log(BNY_WARN, "failed to use PIN provided by askpass",
		    "error", BNY_ERF, err, NULL);
		errf_free(err);
		goto out;
	}
	extend_probe_deadline();
	agent_piv_close(B_FALSE);
	if (pin_len != 0)
		explicit_bzero(pin, pin_len);
	pin_len = strlen(buf);
	bcopy(buf, pin, pin_len);
	bunyan_log(BNY_INFO, "storing PIN in memory", NULL);
	set_probe_interval(B_TRUE);

out:
	explicit_bzero(buf, sizeof(buf));
}

static void
send_touch_notify(socket_entry_t *e, enum piv_slotid slotid)
{
	int status;
	pid_t kid, ret;
	char msg[1024];
	char title[256];
	char *guid;

	if (notify == NULL)
		notify = getenv("SSH_NOTIFY_SEND");
	if (notify == NULL)
		return;

	guid = piv_token_shortid(selk);
	snprintf(title, sizeof (title),
	    "pivy-agent for token %s", guid);
	snprintf(msg, sizeof (msg),
	    "Touch confirmation may be required to use key in slot %02X",
	    slotid);
	free(guid);
	guid = NULL;

	if ((kid = fork()) == -1)
		return;

	if (kid == 0) {
		close(STDOUT_FILENO);
		close(STDIN_FILENO);
		execlp(notify, notify, title, msg, (char *)NULL);
		exit(128);
	}
	while ((ret = waitpid(kid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (ret == -1 || !WIFEXITED(status) ||
	    (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 1)) {
		bunyan_log(BNY_WARN, "executing notify failed",
		    "exit_status", BNY_UINT, (uint)WEXITSTATUS(status),
		    NULL);
		return;
	}
}

static void
try_confirm_client(socket_entry_t *e, enum piv_slotid slotid)
{
	int status;
	pid_t kid, ret;
	boolean_t add_zenity_args = B_FALSE;
	boolean_t add_notify_send_args = B_FALSE;
	char prompt[1024], buf[64];
	size_t len;
	char *guid;
	int p[2];

	if (confirm_mode == C_NEVER) {
		e->se_authz = AUTHZ_ALLOWED;
		return;
	}

	if (confirm_mode == C_FORWARDED) {
		const char *ssh = NULL;
		const size_t len = strlen(e->se_exepath);
		const uint64_t now = monotime();
		const int64_t delta = now - e->se_pid_ent->pe_last_auth;
		/*
		 * If we've seen a session-bind for auth, this isn't a
		 * forwarded connection.
		 */
		if (e->se_sbind == SESSBIND_AUTH) {
			e->se_authz = AUTHZ_ALLOWED;
			return;
		}
		/*
		 * If we haven't seen a session-bind at all, sniff whether this
		 * is an "ssh" process connected to us. If this is the very
		 * first connection that "ssh" process has made, assume it's
		 * the auth socket.
		 */
		if (e->se_sbind == SESSBIND_NONE) {
			if (len >= 4)
				ssh = &e->se_exepath[len - 4];
			if (ssh != NULL && strcmp(ssh, "/ssh") != 0)
				ssh = NULL;
			if (len == 3 && strcmp(e->se_exepath, "ssh") == 0)
				ssh = e->se_exepath;
			if (e->se_pid_idx == 0 || ssh == NULL) {
				e->se_authz = AUTHZ_ALLOWED;
				return;
			}
		}
		/*
		 * Otherwise, check if the user has authorised this PID
		 * recently -- if they have, this connection is ok (and we
		 * should renew the PID's authorisation).
		 */
		if (e->se_pid_ent->pe_pid != 0 &&
		    pid_auth_cache_time > 0 &&
		    delta < pid_auth_cache_time) {
			e->se_pid_ent->pe_last_auth = now;
			e->se_authz = AUTHZ_ALLOWED;
			return;
		}
	}

	/* Otherwise we're going to try to obtain user consent. */

	if (askpass == NULL)
		askpass = getenv("SSH_ASKPASS");
	if (confirm == NULL)
		confirm = getenv("SSH_CONFIRM");
	if (askpass == NULL && confirm == NULL) {
		e->se_authz = AUTHZ_DENIED;
		return;
	}

	if (confirm != NULL) {
		char *tmp = strdup(confirm);
		const char *execname = basename(tmp);
		if (strcmp(execname, "zenity") == 0)
			add_zenity_args = B_TRUE;
		if (strcmp(execname, "notify-send") == 0)
			add_notify_send_args = B_TRUE;
		free(tmp);
	}

	bunyan_log(BNY_INFO, "requesting user confirmation",
	    "exec", BNY_STRING, confirm,
	    "zenity", BNY_INT, add_zenity_args,
	    "notify-send", BNY_INT, add_notify_send_args,
	    NULL);

	guid = piv_token_shortid(selk);
	snprintf(prompt, sizeof (prompt),
	    "%sA new client is trying to use PIV token %s\r\n\r\n"
	    "Client PID: %d\r\nClient executable: %s\r\nClient cmd: %s\r\n"
	    "Slot requested: %02x",
	    (add_zenity_args ? "--text=" : ""),
	    guid, (int)e->se_pid,
	    (e->se_exepath == NULL) ? "(unknown)" : e->se_exepath,
	    (e->se_exeargs == NULL) ? "(unknown)" : e->se_exeargs,
	    (uint)slotid);
	free(guid);
	guid = NULL;

	if (pipe(p) == -1)
		return;
	if ((kid = fork()) == -1)
		return;
	if (kid == 0) {
		close(STDOUT_FILENO);
		close(STDIN_FILENO);
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) == -1)
			exit(1);
		if (confirm && add_zenity_args) {
			execlp(confirm, confirm,
			    "--question", "--ok-label=Allow",
			    "--cancel-label=Block", "--width=300",
			    "--title=pivy-agent",
			    "--icon-name=application-certificate-symbolic",
			    prompt,
			    (char *)NULL);
		} else if (confirm && add_notify_send_args) {
			execlp(confirm, confirm,
			    "--app-name=pivy-agent",
			    "--icon=user-info",
			    "--urgency=critical",
			    "--expire-time=0",
			    "--wait",
			    "--action=allow=Allow",
			    "--action=deny=Deny",
			    "pivy-agent confirmation",
			    prompt,
			    (char *)NULL);
		} else if (confirm) {
			execlp(confirm, confirm, prompt, (char *)NULL);
		} else {
			setenv("SSH_ASKPASS_PROMPT", "confirm", 1);
			execlp(askpass, askpass, prompt, (char *)NULL);
		}
		exit(128);
	}
	close(p[1]);
	while ((ret = waitpid(kid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (ret == -1 || !WIFEXITED(status) ||
	    (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 1)) {
		bunyan_log(BNY_WARN, "executing confirm failed",
		    "exit_status", BNY_UINT, (uint)WEXITSTATUS(status),
		    NULL);
		return;
	}

	len = 0;
	do {
		ssize_t r = read(p[0], buf + len, sizeof(buf) - 1 - len);

		if (r == -1 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		len += r;
	} while (sizeof(buf) - 1 - len > 0);
	buf[len] = '\0';

	close(p[0]);

	if (WEXITSTATUS(status) == 0 && (!add_notify_send_args ||
	    strcmp(buf, "allow\n") == 0)) {
		e->se_authz = AUTHZ_ALLOWED;
		e->se_pid_ent->pe_last_auth = monotime();
	} else {
		e->se_authz = AUTHZ_DENIED;
	}
}

static errf_t *
agent_piv_try_pin(boolean_t canskip)
{
	errf_t *err = NULL;
	uint retries = 1;
	if (pin_len == 0 && !canskip)
		try_askpass();
	if (pin_len != 0) {
		err = piv_verify_pin(selk, piv_token_default_auth(selk),
		    pin, &retries, canskip);
		if (err == ERRF_OK)
			extend_probe_deadline();
		err = wrap_pin_error(err, retries);
	}
	return (err);
}

static uint64_t
get_pid_start_time(pid_t pid)
{
	uint64_t val = 0;
#if defined(__sun) || defined(__linux__)
	FILE *f;
	char fn[128];
#endif

#if defined(__OpenBSD__)
	struct kinfo_proc kp;
	int mib[6] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid,
	    sizeof (kp), 1 };
	size_t sz = sizeof (kp);

	if (sysctl(mib, 6, &kp, &sz, NULL, 0) == 0)
		val = kp.p_ustart_sec;
#endif
#if defined(__sun)
	struct psinfo *psinfo;

	psinfo = calloc(1, sizeof (struct psinfo));
	snprintf(fn, sizeof (fn), "/proc/%d/psinfo", (int)pid);
	f = fopen(fn, "r");
	if (f != NULL) {
		if (fread(psinfo, sizeof (struct psinfo), 1, f) == 1) {
			val = psinfo->pr_start.tv_sec;
			val *= 1000;
			val += psinfo->pr_start.tv_nsec / 1000000;
		}
		fclose(f);
	}
	free(psinfo);
#endif
#if defined(__APPLE__)
	struct proc_bsdinfo pinfo;
	int rc;

	rc = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pinfo, sizeof (pinfo));
	if (rc >= sizeof (pinfo)) {
		val = pinfo.pbi_start_tvsec;
		val *= 1000;
		val += pinfo.pbi_start_tvusec / 1000;
	}
#endif
#if defined(__linux__)
	char ln[1024];
	size_t len;
	uint i = 0, j = 0;
	char *last = ln;
	char *p;

	snprintf(fn, sizeof (fn), "/proc/%d/stat", (int)pid);
	f = fopen(fn, "r");
	if (f != NULL) {
		len = fread(ln, 1, sizeof (ln) - 1, f);
		fclose(f);

		/*
		 * The stat file is an annoying format which we will have to
		 * parse by hand -- the (cmd) field might have spaces in it.
		 */
		for (i = 0; i < len; ++i) {
			if (ln[i] == ' ') {
				ln[i] = '\0';
				++j;
				if (j == 22) {
					unsigned long long int parsed;
					errno = 0;
					parsed = strtoull(last, &p, 10);
					if (errno == 0 && *p == '\0') {
						val = parsed;
						break;
					}
				}
				last = &ln[i+1];
			} else if (ln[i] == '(') {
				for (; i < len; ++i) {
					if (ln[i] == ')')
						break;
				}
			}
		}
	}
#endif
	return (val);
}

static struct pid_entry *
find_or_make_pid_entry(pid_t pid, uint64_t start_time)
{
	uint i;
	uint64_t now = monotime();
	uint npids_alloc;

	for (i = 0; i < pids_alloc; ++i) {
		if (pids[i].pe_valid && pids[i].pe_pid == pid &&
		    pids[i].pe_start_time == start_time) {
			pids[i].pe_time = now;
			return (&pids[i]);
		}
		if (pids[i].pe_valid && pids[i].pe_pid == pid) {
			pids[i].pe_time = now;
			pids[i].pe_start_time = start_time;
			pids[i].pe_conn_count = 0;
			pids[i].pe_last_auth = 0;
			return (&pids[i]);
		}
		if (pids[i].pe_valid) {
			uint64_t delta = now - pids[i].pe_time;
			if (delta > 30000) {
				uint64_t nstart;
				nstart = get_pid_start_time(pids[i].pe_pid);
				if (nstart == 0 ||
				    nstart != pids[i].pe_start_time) {
					pids[i].pe_valid = B_FALSE;
				}
			}
		}
	}

	for (i = 0; i < pids_alloc; ++i) {
		if (!pids[i].pe_valid)
			goto newpid;
	}

	npids_alloc = pids_alloc + 128;
	pids = reallocarray(pids, npids_alloc, sizeof (pid_entry_t));
	VERIFY(pids != NULL);
	for (i = pids_alloc; i < npids_alloc; ++i)
		pids[i].pe_valid = B_FALSE;
	i = pids_alloc;
	pids_alloc = npids_alloc;
newpid:
	pids[i].pe_valid = B_TRUE;
	pids[i].pe_pid = pid;
	pids[i].pe_start_time = start_time;
	pids[i].pe_time = now;
	pids[i].pe_conn_count = 0;
	pids[i].pe_last_auth = 0;
	return (&pids[i]);
}

static void
init_socket(socket_entry_t *e)
{
	bzero(e, sizeof (*e));
	e->se_fd = -1;
	e->se_type = AUTH_UNUSED;
	e->se_authz = AUTHZ_NOT_YET;
	e->se_sbind = SESSBIND_NONE;
}

static void
close_socket(socket_entry_t *e)
{
	close(e->se_fd);
	e->se_fd = -1;
	e->se_type = AUTH_UNUSED;
	e->se_authz = AUTHZ_NOT_YET;
	e->se_pid_ent = NULL;
	e->se_sbind = SESSBIND_NONE;
	sshbuf_free(e->se_input);
	e->se_input = NULL;
	sshbuf_free(e->se_output);
	e->se_output = NULL;
	sshbuf_free(e->se_request);
	e->se_request = NULL;
	free(e->se_exepath);
	e->se_exepath = NULL;
	free(e->se_exeargs);
	e->se_exeargs = NULL;
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
send_status(socket_entry_t *e, int success)
{
	int r;

	if ((r = sshbuf_put_u32(e->se_output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->se_output, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

static void
send_extfail(socket_entry_t *e)
{
	int r;

	if ((r = sshbuf_put_u32(e->se_output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->se_output, SSH_AGENT_EXT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

/* send list of supported public keys to 'client' */
static errf_t *
process_request_identities(socket_entry_t *e)
{
	struct sshbuf *msg;
	struct piv_slot *slot = NULL;
	char comment[256];
	uint64_t now;
	int r, n;
	errf_t *err = NULL;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if ((err = agent_piv_open()))
		goto out;

	now = monotime();
	if ((now - last_update) >= card_probe_interval * 1000) {
		last_update = now;
		err = piv_read_all_certs(selk);
		errf_free(err);
		if (cak != NULL && (err = auth_cak())) {
			agent_piv_close(B_TRUE);
			drop_pin();
			goto out;
		}
	}
	agent_piv_close(B_FALSE);

	n = 0;
	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (!is_slot_enabled(slot) ||
		    piv_slot_pubkey(slot) == NULL)
			continue;
		++n;
	}

	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (piv_slot_id(slot) == PIV_SLOT_KEY_MGMT ||
		    piv_slot_pubkey(slot) == NULL)
			continue;
		if (!is_slot_enabled(slot))
			continue;
		comment[0] = 0;
		snprintf(comment, sizeof (comment), "PIV_slot_%02X %s",
		    piv_slot_id(slot), piv_slot_subject(slot));
		if ((r = sshkey_puts(piv_slot_pubkey(slot), msg)) != 0 ||
		    (r = sshbuf_put_cstring(msg, comment)) != 0) {
			fatal("%s: put key/comment: %s", __func__,
			    ssh_err(r));
		}
	}
	/*
	 * Always put key mgmt last so that SSH clients not aware of the fact
	 * that this slot is not used for signing by default will be unlikely
	 * to try using it.
	 */
	if ((slot = piv_get_slot(selk, PIV_SLOT_KEY_MGMT)) != NULL &&
	    is_slot_enabled(slot) && piv_slot_pubkey(slot) != NULL) {
		comment[0] = 0;
		snprintf(comment, sizeof (comment), "PIV_slot_%02X %s",
		    piv_slot_id(slot), piv_slot_subject(slot));
		if ((r = sshkey_puts(piv_slot_pubkey(slot), msg)) != 0 ||
		    (r = sshbuf_put_cstring(msg, comment)) != 0) {
			fatal("%s: put key/comment: %s", __func__,
			    ssh_err(r));
		}
	}
	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	sshbuf_free(msg);
	return (err);
}

/* ssh2 only */
static errf_t *
process_sign_request2(socket_entry_t *e)
{
	const u_char *data;
	u_char *signature = NULL;
	u_char *rawsig = NULL;
	size_t dlen, rslen = 0, slen = 0;
	u_int flags;
	int r;
	errf_t *err = NULL;
	struct sshbuf *msg;
	struct sshbuf *buf;
	struct sshkey *key = NULL;
	struct piv_slot *slot = NULL;
	int found = 0;
	enum sshdigest_types hashalg, ohashalg;
	boolean_t canskip = B_TRUE;
	enum piv_slot_auth rauth;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(e->se_request, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(e->se_request, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_u32(e->se_request, &flags)) != 0) {
		err = parserrf("sshbuf_get_string", r);
		goto out;
	}

	if ((err = agent_piv_open()))
		goto out;

	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (sshkey_equal(piv_slot_pubkey(slot), key)) {
			found = 1;
			break;
		}
	}
	if (!found || slot == NULL || !is_slot_enabled(slot)) {
		agent_piv_close(B_FALSE);
		err = errf("NotFoundError", NULL, "specified key not found");
		goto out;
	}
	bunyan_add_vars(msg_log_frame,
	    "slotid", BNY_UINT, (uint)piv_slot_id(slot), NULL);

	try_confirm_client(e, piv_slot_id(slot));
	if (e->se_authz == AUTHZ_DENIED) {
		err = errf("AuthzError", NULL, "client blocked");
		goto out;
	}

	if (piv_slot_id(slot) == PIV_SLOT_KEY_MGMT && !sign_9d) {
		err = errf("PermissionError", NULL, "key management key (9d) "
		    "is not allowed to sign data without the -m option");
		goto out;
	}

	rauth = piv_slot_get_auth(selk, slot);
	if (rauth & PIV_SLOT_AUTH_PIN)
		canskip = B_FALSE;
	if (rauth & PIV_SLOT_AUTH_TOUCH)
		send_touch_notify(e, piv_slot_id(slot));

pin_again:
	if ((err = agent_piv_try_pin(canskip))) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	if (key->type == KEY_RSA) {
		hashalg = SSH_DIGEST_SHA1;
		if (flags & SSH_AGENT_RSA_SHA2_256)
			hashalg = SSH_DIGEST_SHA256;
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			hashalg = SSH_DIGEST_SHA512;
	} else if (key->type == KEY_ECDSA) {
		switch (sshkey_curve_nid_to_bits(key->ecdsa_nid)) {
		case 256:
			hashalg = SSH_DIGEST_SHA256;
			break;
		case 384:
			hashalg = SSH_DIGEST_SHA384;
			break;
		case 521:
			hashalg = SSH_DIGEST_SHA512;
			break;
		default:
			hashalg = SSH_DIGEST_SHA256;
		}
	} else if (key->type == KEY_ED25519) {
		hashalg = SSH_DIGEST_SHA512;
	} else {
		VERIFY(0);
	}
	ohashalg = hashalg;
	err = piv_sign(selk, slot, data, dlen, &hashalg, &rawsig, &rslen);

	if (errf_caused_by(err, "PermissionError") && pin_len != 0 &&
	    piv_token_is_ykpiv(selk) && canskip) {
		/*
		 * On a YubiKey, slots other than 9C (SIGNATURE) can also be
		 * set to "PIN Always" mode. We might have one, so try again
		 * with forced PIN entry.
		 */
		canskip = B_FALSE;
		goto pin_again;
	} else if (errf_caused_by(err, "PermissionError")) {
		try_askpass();
		if (pin_len != 0) {
			canskip = B_FALSE;
			goto pin_again;
		}
		agent_piv_close(B_TRUE);
		err = nopinerrf(err);
		goto out;
	} else if (err) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	agent_piv_close(B_FALSE);

	if (hashalg != ohashalg) {
		err = errf("HashMismatch", NULL,
		    "PIV device signed with a different hash algorithm to "
		    "the one requested (wanted %d, got %d)",
		    (int)ohashalg, (int)hashalg);
		goto out;
	}

	buf = sshbuf_new();
	VERIFY(buf != NULL);
	VERIFY0(sshkey_sig_from_asn1(piv_slot_pubkey(slot), hashalg,
	    rawsig, rslen, buf));
	explicit_bzero(rawsig, rslen);
	free(rawsig);

	signature = calloc(1, sshbuf_len(buf));
	slen = sshbuf_len(buf);
	VERIFY0(sshbuf_get(buf, signature, slen));
	sshbuf_free(buf);

	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
	    (r = sshbuf_put_string(msg, signature, slen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	sshkey_free(key);
	sshbuf_free(msg);
	explicit_bzero(signature, slen);
	free(signature);
	return (err);
}

static errf_t *
process_remove_all_identities(socket_entry_t *e)
{
	drop_pin();
	send_status(e, 1);
	return (NULL);
}

struct exthandler {
	const char *eh_name;
	boolean_t eh_string;
	errf_t *(*eh_handler)(socket_entry_t *, struct sshbuf *);
};
struct exthandler exthandlers[];

static errf_t *
process_ext_ecdh(socket_entry_t *e, struct sshbuf *buf)
{
	int r;
	errf_t *err;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct sshkey *partner = NULL;
	struct piv_slot *slot = NULL;
	uint8_t *secret;
	size_t seclen;
	uint flags;
	int found = 0;
	boolean_t canskip = B_TRUE;
	enum piv_slot_auth rauth;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(buf, &key)) ||
	    (r = sshkey_froms(buf, &partner))) {
		err = parserrf("sshkey_froms", r);
		goto out;
	}
	if ((r = sshbuf_get_u32(buf, &flags))) {
		err = parserrf("sshbuf_get_u32(flags)", r);
		goto out;
	}

	if (flags != 0) {
		err = flagserrf(flags);
		goto out;
	}

	if ((err = agent_piv_open()))
		goto out;

	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (sshkey_equal(piv_slot_pubkey(slot), key) == 1) {
			found = 1;
			break;
		}
	}
	if (!found || !is_slot_enabled(slot)) {
		agent_piv_close(B_FALSE);
		err = errf("NotFoundError", NULL, "specified key not found");
		goto out;
	}
	bunyan_add_vars(msg_log_frame,
	    "slotid", BNY_UINT, (uint)piv_slot_id(slot), NULL);

	try_confirm_client(e, piv_slot_id(slot));
	if (e->se_authz == AUTHZ_DENIED) {
		err = errf("AuthzError", NULL, "client blocked");
		goto out;
	}

	if (key->type != KEY_ECDSA || partner->type != KEY_ECDSA) {
		agent_piv_close(B_FALSE);
		err = errf("InvalidKeysError", NULL,
		    "keys are not both EC keys (%s and %s)",
		    sshkey_type(key), sshkey_type(partner));
		goto out;
	}

	rauth = piv_slot_get_auth(selk, slot);
	if (rauth & PIV_SLOT_AUTH_PIN)
		canskip = B_FALSE;
	if (rauth & PIV_SLOT_AUTH_TOUCH)
		send_touch_notify(e, piv_slot_id(slot));

pin_again:
	if ((err = agent_piv_try_pin(canskip))) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	err = piv_ecdh(selk, slot, partner, &secret, &seclen);
	if (errf_caused_by(err, "PermissionError") && pin_len != 0 &&
	    piv_token_is_ykpiv(selk) && canskip) {
		/* Yubikey can have slots other than 9C as "PIN Always" */
		canskip = B_FALSE;
		goto pin_again;
	} else if (errf_caused_by(err, "PermissionError")) {
		try_askpass();
		if (pin_len != 0) {
			canskip = B_FALSE;
			goto pin_again;
		}
		agent_piv_close(B_TRUE);
		err = nopinerrf(err);
		goto out;
	} else if (err) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	agent_piv_close(B_FALSE);

	bunyan_log(BNY_INFO, "performed ECDH operation",
	    "partner_pk", BNY_SSHKEY, partner,
	    NULL);

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_string(msg, secret, seclen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	explicit_bzero(secret, seclen);
	free(secret);

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	sshbuf_free(msg);
	sshkey_free(key);
	sshkey_free(partner);
	return (err);
}

static errf_t *
process_ext_rebox(socket_entry_t *e, struct sshbuf *buf)
{
	int r;
	errf_t *err;
	struct sshbuf *msg, *boxbuf = NULL, *guidb = NULL;
	struct sshkey *partner = NULL;
	struct piv_ecdh_box *box = NULL, *newbox = NULL;
	uint8_t slotid;
	uint flags;
	struct piv_slot *slot;
	struct piv_token *tk;
	uint8_t *secret = NULL, *out = NULL;
	size_t seclen, outlen;
	boolean_t canskip = B_TRUE;
	enum piv_slot_auth rauth;
	char *slotstr;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_froms(buf, &boxbuf)) != 0 ||
	    (r = sshbuf_froms(buf, &guidb)) != 0) {
		err = parserrf("sshbuf_froms", r);
		goto out;
	}
	if ((r = sshbuf_get_u8(buf, &slotid)) != 0) {
		err = parserrf("sshbuf_get_u8(slotid)", r);
		goto out;
	}
	if ((r = sshkey_froms(buf, &partner)) != 0) {
		err = parserrf("sshkey_froms(partner)", r);
		goto out;
	}
	if ((r = sshbuf_get_u32(buf, &flags)) != 0) {
		err = parserrf("sshbuf_get_u32(flags)", r);
		goto out;
	}

	if (flags != 0) {
		err = flagserrf(flags);
		goto out;
	}

	try_confirm_client(e, PIV_SLOT_KEY_MGMT);
	if (e->se_authz == AUTHZ_DENIED) {
		err = errf("AuthzError", NULL, "client blocked");
		goto out;
	}

	err = sshbuf_get_piv_box(boxbuf, &box);
	if (err)
		goto out;

	err = piv_box_find_token(selk, box, &tk, &slot);
	if (err)
		goto out;
	if (tk != selk) {
		err = errf("WrongTokenError", NULL, "box can only be unlocked "
		    "by a different PIV device");
		goto out;
	}
	if (!is_slot_enabled(slot)) {
		err = errf("KeyDisabledError", NULL, "box can only be unlocked "
		    "by a disabled key slot");
		goto out;
	}

	rauth = piv_slot_get_auth(tk, slot);
	if (rauth & PIV_SLOT_AUTH_PIN)
		canskip = B_FALSE;
	if (rauth & PIV_SLOT_AUTH_TOUCH)
		send_touch_notify(e, piv_slot_id(slot));

	if ((err = agent_piv_open()))
		goto out;
pin_again:
	if ((err = agent_piv_try_pin(canskip))) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	err = piv_box_open(selk, slot, box);
	if (errf_caused_by(err, "PermissionError") && pin_len != 0 &&
	    piv_token_is_ykpiv(selk) && canskip) {
		/*
		 * On a Yubikey, slots other than 9C (SIGNATURE) can also be
		 * set to "PIN Always" mode. We might have one, so try again
		 * with forced PIN entry.
		 */
		canskip = B_FALSE;
		goto pin_again;
	} else if (errf_caused_by(err, "PermissionError")) {
		try_askpass();
		if (pin_len != 0) {
			canskip = B_FALSE;
			goto pin_again;
		}
		agent_piv_close(B_TRUE);
		err = nopinerrf(err);
		goto out;
	} else if (err) {
		agent_piv_close(B_TRUE);
		goto out;
	}

	slotstr = piv_slotid_to_string(piv_slot_id(slot));
	bunyan_log(BNY_INFO, "opened ECDH box",
	    "key_slot", BNY_STRING, slotstr,
	    "partner_pk", BNY_SSHKEY, partner,
	    "ephem_pk", BNY_SSHKEY, piv_box_ephem_pubkey(box),
	    "payload_size", BNY_SIZE_T, piv_box_encsize(box),
	    NULL);
	free(slotstr);

	VERIFY0(piv_box_take_data(box, &secret, &seclen));
	agent_piv_close(B_FALSE);


	newbox = piv_box_new();
	VERIFY(newbox != NULL);

	if (sshbuf_len(guidb) > 0) {
		piv_box_set_guid(newbox, sshbuf_ptr(guidb), GUID_LEN);
		piv_box_set_slot(newbox, slotid);
	}
	VERIFY0(piv_box_set_data(newbox, secret, seclen));
	if ((err = piv_box_seal_offline(partner, newbox)))
		goto out;

	VERIFY0(piv_box_to_binary(newbox, &out, &outlen));

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_string(msg, out, outlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	piv_box_free(box);
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
	sshbuf_free(guidb);
	return (err);
}

static errf_t *
process_ext_x509_certs(socket_entry_t *e, struct sshbuf *buf)
{
	int rc;
	struct sshbuf *msg;
	u_int flags;
	struct sshkey *key = NULL;
	errf_t *err = ERRF_OK;
	int found = 0;
	struct piv_slot *slot = NULL;
	X509 *x509;
	uint8_t *cbuf = NULL;
	size_t clen;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if ((rc = sshkey_froms(buf, &key)) != 0 ||
	    (rc = sshbuf_get_u32(buf, &flags)) != 0) {
		err = parserrf("sshbuf_get_string", rc);
		goto out;
	}

	if (flags != 0) {
		err = errf("UnsupportedFlagsError", NULL, "request specified "
		    "non-zero flags, but none are supported");
		goto out;
	}

	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (sshkey_equal(piv_slot_pubkey(slot), key)) {
			found = 1;
			break;
		}
	}
	if (!found || slot == NULL || !is_slot_enabled(slot)) {
		err = errf("NotFoundError", NULL, "specified key not found");
		goto out;
	}

	x509 = piv_slot_cert(slot);
	rc = i2d_X509(x509, &cbuf);
	if (rc < 0) {
		make_sslerrf(err, "i2d_X509", "converting X509 cert "
		    "to DER");
		err = errf("BadCertError", err, "key in slot %02X cert failed "
		    "to convert", piv_slot_id(slot));
		goto out;
	}
	clen = rc;

	if ((rc = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (rc = sshbuf_put_string(msg, cbuf, clen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(rc));

	if ((rc = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(rc));

out:
	sshkey_free(key);
	sshbuf_free(msg);
	OPENSSL_free(cbuf);
	return (err);
}

static errf_t *
process_ext_prehash(socket_entry_t *e, struct sshbuf *inbuf)
{
	const u_char *data;
	u_char *signature = NULL;
	u_char *rawsig = NULL;
	size_t dlen, rslen = 0;
	u_int flags;
	int r;
	errf_t *err = NULL;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct piv_slot *slot = NULL;
	int found = 0;
	boolean_t canskip = B_TRUE;
	enum piv_slot_auth rauth;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if ((r = sshkey_froms(inbuf, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(inbuf, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_u32(inbuf, &flags)) != 0) {
		err = parserrf("sshbuf_get_string", r);
		goto out;
	}

	if ((err = agent_piv_open()))
		goto out;

	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (sshkey_equal(piv_slot_pubkey(slot), key)) {
			found = 1;
			break;
		}
	}
	if (!found || slot == NULL || !is_slot_enabled(slot)) {
		agent_piv_close(B_FALSE);
		err = errf("NotFoundError", NULL, "specified key not found");
		goto out;
	}
	bunyan_add_vars(msg_log_frame,
	    "slotid", BNY_UINT, (uint)piv_slot_id(slot), NULL);

	try_confirm_client(e, piv_slot_id(slot));
	if (e->se_authz == AUTHZ_DENIED) {
		err = errf("AuthzError", NULL, "client blocked");
		goto out;
	}

	if (piv_slot_id(slot) == PIV_SLOT_KEY_MGMT && !sign_9d) {
		err = errf("PermissionError", NULL, "key management key (9d) "
		    "is not allowed to sign data without the -m option");
		goto out;
	}

	rauth = piv_slot_get_auth(selk, slot);
	if (rauth & PIV_SLOT_AUTH_PIN)
		canskip = B_FALSE;
	if (rauth & PIV_SLOT_AUTH_TOUCH)
		send_touch_notify(e, piv_slot_id(slot));

pin_again:
	if ((err = agent_piv_try_pin(canskip))) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	err = piv_sign_prehash(selk, slot, data, dlen, &rawsig, &rslen);

	if (errf_caused_by(err, "PermissionError") && pin_len != 0 &&
	    piv_token_is_ykpiv(selk) && canskip) {
		/*
		 * On a Yubikey, slots other than 9C (SIGNATURE) can also be
		 * set to "PIN Always" mode. We might have one, so try again
		 * with forced PIN entry.
		 */
		canskip = B_FALSE;
		goto pin_again;
	} else if (errf_caused_by(err, "PermissionError")) {
		try_askpass();
		if (pin_len != 0) {
			canskip = B_FALSE;
			goto pin_again;
		}
		agent_piv_close(B_TRUE);
		err = nopinerrf(err);
		goto out;
	} else if (err) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	agent_piv_close(B_FALSE);

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_string(msg, rawsig, rslen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	sshkey_free(key);
	sshbuf_free(msg);
	explicit_bzero(rawsig, rslen);
	free(rawsig);
	free(signature);
	return (err);
}

static errf_t *
process_ext_sessbind(socket_entry_t *e, struct sshbuf *buf)
{
	int r;
	errf_t *err = ERRF_OK;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	uint8_t is_forwarding = 1;
	sessbind_t new_sbind;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if ((r = sshkey_froms(buf, &key)) ||
	    (r = sshbuf_skip_string(buf)) ||	/* session id */
	    (r = sshbuf_skip_string(buf)) ||	/* signature */
	    (r = sshbuf_get_u8(buf, &is_forwarding))) {
		err = ssherrf("sshbuf_get", r);
		goto out;
	}

	new_sbind = (is_forwarding == 0) ? SESSBIND_AUTH : SESSBIND_FWD;

	if (e->se_sbind == SESSBIND_NONE) {
		e->se_sbind = new_sbind;
		bunyan_log(BNY_INFO, "session-bind marking connection",
		    "sbind_state", BNY_STRING, (is_forwarding == 0) ? "auth" :
		    "forwarding", NULL);
	} else if (e->se_sbind == SESSBIND_AUTH && new_sbind != e->se_sbind) {
		e->se_sbind = new_sbind;
		e->se_authz = AUTHZ_DENIED;
		bunyan_log(BNY_WARN, "connection has a session-bind for auth, "
		    " but has now sent a forwarding bind", NULL);
	}

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_u32(msg, 2)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	sshbuf_free(msg);
	sshkey_free(key);
	return (err);
}

static errf_t *
process_ext_attest(socket_entry_t *e, struct sshbuf *buf)
{
	int r;
	errf_t *err;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct piv_slot *slot = NULL;
	uint8_t *cert = NULL, *chain = NULL, *ptr;
	size_t certlen, chainlen = 0, len;
	uint flags;
	int found = 0;
	uint tag;
	struct tlv_state *tlv = NULL;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(buf, &key)) != 0 ||
	    (r = sshbuf_get_u32(buf, &flags)) != 0) {
		err = parserrf("sshkey_froms", r);
		goto out;
	}

	if (flags != 0) {
		err = flagserrf(flags);
		goto out;
	}

	if ((err = agent_piv_open()))
		goto out;

	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (sshkey_equal(piv_slot_pubkey(slot), key)) {
			found = 1;
			break;
		}
	}
	if (!found || !is_slot_enabled(slot)) {
		agent_piv_close(B_FALSE);
		err = errf("NotFoundError", NULL, "specified key not found");
		goto out;
	}
	bunyan_add_vars(msg_log_frame,
	    "slotid", BNY_UINT, (uint)piv_slot_id(slot), NULL);

	err = ykpiv_attest(selk, slot, &cert, &certlen);
	if (err) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	err = piv_read_file(selk, PIV_TAG_CERT_YK_ATTESTATION, &chain, &chainlen);
	if (err) {
		agent_piv_close(B_TRUE);
		goto out;
	}
	agent_piv_close(B_FALSE);

	tlv = tlv_init(chain, 0, chainlen);
	if ((err = tlv_read_tag(tlv, &tag)))
		goto out;
	if (tag != 0x70) {
		err = errf("InvalidDataError", NULL, "PIV device returned "
		    "wrong tag at start of attestation cert");
		goto out;
	}
	ptr = tlv_ptr(tlv);
	len = tlv_rem(tlv);
	tlv_skip(tlv);

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_u32(msg, 2)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_string(msg, cert, certlen)) != 0 ||
	    (r = sshbuf_put_string(msg, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	if (tlv != NULL)
		tlv_free(tlv);
	free(cert);
	piv_file_data_free(chain, chainlen);
	sshbuf_free(msg);
	sshkey_free(key);
	return (err);
}

static errf_t *
process_ext_query(socket_entry_t *e, struct sshbuf *buf)
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

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);

	return (NULL);
}

struct exthandler exthandlers[] = {
{ "query", 				B_FALSE,	process_ext_query },
{ "ecdh@joyent.com", 			B_TRUE,		process_ext_ecdh },
{ "ecdh-rebox@joyent.com", 		B_TRUE,		process_ext_rebox },
{ "x509-certs@joyent.com", 		B_FALSE,	process_ext_x509_certs },
{ "ykpiv-attest@joyent.com", 		B_TRUE,		process_ext_attest },
{ "session-bind@openssh.com", 		B_FALSE,	process_ext_sessbind },
{ "sign-prehash@arekinath.github.io",	B_FALSE,	process_ext_prehash },
{ NULL, B_FALSE, NULL }
};

static errf_t *
process_extension(socket_entry_t *e)
{
	errf_t *err;
	int r;
	char *extname = NULL;
	size_t enlen;
	struct sshbuf *inner = NULL;
	struct exthandler *h, *hdlr = NULL;

	if ((r = sshbuf_get_cstring(e->se_request, &extname, &enlen)))
		return (parserrf("sshbuf_get_cstring", r));
	VERIFY(extname != NULL);

	for (h = exthandlers; h->eh_name != NULL; ++h) {
		if (strcmp(h->eh_name, extname) == 0) {
			hdlr = h;
			break;
		}
	}
	if (hdlr == NULL) {
		err = errf("UnknownExtension", NULL,
		    "unsupported extension '%s'", extname);
		goto out;
	}

	bunyan_add_vars(msg_log_frame,
	    "extension", BNY_STRING, h->eh_name, NULL);

	if (h->eh_string) {
		if ((r = sshbuf_froms(e->se_request, &inner))) {
			err = parserrf("sshbuf_froms", r);
			goto out;
		}
	} else {
		inner = e->se_request;
	}
	VERIFY(inner != NULL);

	err = hdlr->eh_handler(e, inner);

	if (err) {
		send_extfail(e);
		bunyan_log(BNY_WARN, "failed to process extension command",
		    "error", BNY_ERF, err, NULL);
		if (errf_caused_by(err, "NoPINError") &&
		    bunyan_get_level() > BNY_WARN) {
			warnfx(err, "denied command due to lack of PIN");
		}
		errf_free(err);
		err = ERRF_OK;
	}

out:
	if (h->eh_string)
		sshbuf_free(inner);
	free(extname);
	return (err);
}

static errf_t *
process_lock_agent(socket_entry_t *e, int lock)
{
	int r;
	char *passwd;
	size_t pwlen;
	uint retries = 1;
	errf_t *err = NULL;

	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	if ((r = sshbuf_get_cstring(e->se_request, &passwd, &pwlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	VERIFY(passwd != NULL);

	if (lock) {
		drop_pin();
		send_status(e, 1);
	} else {
		/*
		 * If they sent an empty password, return the current lock
		 * status. This is an easy way to test whether the agent
		 * is currently unlocked or not.
		 */
		if (pwlen == 0) {
			if (pin_len == 0)
				send_status(e, 0);
			else
				send_status(e, 1);
			goto out;
		}

		if ((err = valid_pin(passwd)))
			goto out;

		if ((err = agent_piv_open()))
			goto out;

		err = piv_verify_pin(selk, piv_token_default_auth(selk),
		    passwd, &retries, B_FALSE);

		if (err == ERRF_OK) {
			extend_probe_deadline();
			agent_piv_close(B_FALSE);
			if (pin_len != 0)
				explicit_bzero(pin, pin_len);
			pin_len = pwlen;
			bcopy(passwd, pin, pwlen + 1);
			send_status(e, 1);
			bunyan_log(BNY_INFO, "storing PIN in memory", NULL);
			set_probe_interval(B_TRUE);
			goto out;
		}
		agent_piv_close(B_TRUE);

		err = wrap_pin_error(err, retries);
	}
out:
	explicit_bzero(passwd, pwlen);
	free(passwd);
	return (err);
}

static const char *
msg_type_to_name(int msg)
{
	switch (msg) {
	case SSH_AGENTC_LOCK:
		return ("LOCK");
	case SSH_AGENTC_UNLOCK:
		return ("UNLOCK");
	case SSH2_AGENTC_SIGN_REQUEST:
		return ("SIGN_REQUEST");
	case SSH2_AGENTC_ADD_IDENTITY:
		return ("ADD_IDENTITY");
	case SSH2_AGENTC_REMOVE_IDENTITY:
		return ("REMOVE_IDENTITY");
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		return ("REQUEST_IDENTITIES");
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		return ("REMOVE_ALL_IDENTITIES");
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
		return ("ADD_SMARTCARD_KEY");
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		return ("REMOVE_SMARTCARD_KEY");
	case SSH_AGENTC_EXTENSION:
		return ("EXTENSION");
	default:
		return ("UNKNOWN");
	}
}

/* dispatch incoming messages */
static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	errf_t *err;
	socket_entry_t *e;

	if (socknum >= sockets_alloc) {
		fatal("%s: socket number %u >= allocated %u",
		    __func__, socknum, sockets_alloc);
	}
	e = &sockets[socknum];

	if (sshbuf_len(e->se_input) < 5)
		return 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->se_input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		sdebug("%s: socket %u (fd=%d) message too long %u > %u",
		    __func__, socknum, e->se_fd, msg_len, AGENT_MAX_LEN);
		return -1;
	}
	if (sshbuf_len(e->se_input) < msg_len + 4)
		return 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->se_request);
	if ((r = sshbuf_get_stringb(e->se_input, e->se_request)) != 0 ||
	    (r = sshbuf_get_u8(e->se_request, &type)) != 0) {
		if (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			sdebug("%s: buffer error: %s", __func__, ssh_err(r));
			return -1;
		}
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	msg_log_frame = bunyan_push(
	    "fd", BNY_INT, e->se_fd,
	    "msg_type", BNY_INT, (int)type,
	    "msg_type_name", BNY_STRING, msg_type_to_name(type),
	    "remote_uid", BNY_INT, (int)e->se_uid,
	    "remote_pid", BNY_INT, (int)e->se_pid,
	    "remote_cmd", BNY_STRING,
	    (e->se_exepath == NULL) ? "???" : e->se_exepath,
#if defined(__sun)
	    "remote_zid", BNY_INT, (int)e->se_zid,
	    "remote_zone", BNY_STRING, e->se_zname,
#endif
	    NULL);
	bunyan_log(BNY_DEBUG, "received ssh-agent message", NULL);

	switch (type) {
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		err = process_lock_agent(e, type == SSH_AGENTC_LOCK);
		break;
	/* ssh2 */
	case SSH2_AGENTC_SIGN_REQUEST:
		err = process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		err = process_request_identities(e);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		err = process_remove_all_identities(e);
		break;
	case SSH_AGENTC_EXTENSION:
		err = process_extension(e);
		break;
	default:
		/* Unknown message.  Respond with failure. */
		err = errf("UnknownMessageError", NULL,
		    "unknown/unsupported agent protocol message %d", type);
		break;
	}

	if (err) {
		bunyan_log(BNY_WARN, "failed to process command",
		    "error", BNY_ERF, err, NULL);
		if (errf_caused_by(err, "NoPINError") &&
		    bunyan_get_level() > BNY_WARN) {
			warnfx(err, "denied command due to lack of PIN");
		}
		sshbuf_reset(e->se_request);
		send_status(e, 0);
		errf_free(err);
	} else {
		bunyan_log(BNY_INFO, "processed ssh-agent message", NULL);
	}

	bunyan_pop(msg_log_frame);
	return 0;
}

extern void *reallocarray(void *ptr, size_t nmemb, size_t size);

static socket_entry_t *
new_socket(sock_type_t type, int fd)
{
	u_int i, old_alloc, new_alloc;

	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].se_type == AUTH_UNUSED) {
			sockets[i].se_fd = fd;
			if ((sockets[i].se_input = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].se_output = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].se_request = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			sockets[i].se_type = type;
			return (&sockets[i]);
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = reallocarray(sockets, new_alloc, sizeof(socket_entry_t));
	VERIFY(sockets != NULL);
	for (i = old_alloc; i < new_alloc; i++)
		init_socket(&sockets[i]);
	sockets_alloc = new_alloc;
	sockets[old_alloc].se_fd = fd;
	if ((sockets[old_alloc].se_input = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].se_output = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].se_request = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	sockets[old_alloc].se_type = type;
	return (&sockets[old_alloc]);
}

/*
 * OS-specific check on socket access to the agent. This involves getting
 * info about the connecting client process like its euid, egid, pid etc.
 */
#if defined(__sun)
/*
 * Solaris, illumos etc have getpeerucred(), which returns an opaque ucred_t.
 * We can then use the PID to lookup info in Roger's /proc (which is struct-
 * based, not textual like Linux's procfs).
 */
static int
check_socket_access(int fd, socket_entry_t *ent)
{
	uid_t euid;
	FILE *f;
	ucred_t *peer = NULL;
	struct psinfo *psinfo;
	char fn[128];

	if (getpeerucred(fd, &peer) != 0) {
		error("getpeerucred %d failed: %s", fd, strerror(errno));
		return (0);
	}
	ent->se_uid = (euid = ucred_geteuid(peer));
	ent->se_gid = ucred_getegid(peer);
	ent->se_pid = ucred_getpid(peer);
	ent->se_zid = ucred_getzoneid(peer);
	ent->se_zname[0] = '\0';
	(void) getzonenamebyid(ent->se_zid, ent->se_zname,
	    sizeof (ent->se_zname));
	ucred_free(peer);
	psinfo = calloc(1, sizeof (struct psinfo));
	snprintf(fn, sizeof (fn), "/proc/%d/psinfo", (int)ent->se_pid);
	f = fopen(fn, "r");
	if (f != NULL) {
		if (fread(psinfo, sizeof (struct psinfo), 1, f) == 1) {
			ent->se_exepath = strndup(psinfo->pr_fname,
			    sizeof (psinfo->pr_fname));
			ent->se_exeargs = strndup(psinfo->pr_psargs,
			    sizeof (psinfo->pr_psargs));
		}
		fclose(f);
	}
	free(psinfo);
	if (!allow_any_zoneid && !check_zid(ent->se_zid)) {
		error("zoneid mismatch: peer zoneid %u not on allow list",
		    (u_int) ent->se_zid);
		return (0);
	}
	if (!allow_any_uid && (euid != 0) && !check_uid(euid)) {
		error("uid mismatch: peer euid %u not on allow list",
		    (u_int) euid);
		return (0);
	}

	return (1);
}
#elif defined(__OpenBSD__)
/*
 * OpenBSD has SO_PEERCRED, but with a struct sockpeercred (not a struct ucred
 * like it is on Linux et al). We can get other details via sysctl(2) as well.
 */
static int
check_socket_access(int fd, socket_entry_t *ent)
{
	struct sockpeercred *peer;
	socklen_t len;
	uid_t euid;
	struct kinfo_proc kp;
	int mib[6] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0, sizeof (kp), 1 };
	size_t sz;
	errf_t *err;

	peer = calloc(1, sizeof (struct sockpeercred));
	len = sizeof (struct sockpeercred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, peer, &len)) {
		error("getsockopts(SO_PEERCRED) %d failed: %s", fd,
		    strerror(errno));
		free(peer);
		return (0);
	}
	ent->se_uid = (euid = peer->uid);
	ent->se_gid = peer->gid;
	ent->se_pid = peer->pid;
	free(peer);

	mib[3] = (int)ent->se_pid;
	sz = sizeof (kp);
	if (sysctl(mib, 6, &kp, &sz, NULL, 0)) {
		err = errfno("sysctl", errno, "reading KERN_PROC");
		bunyan_log(BNY_DEBUG, "failed to get sysctl info about pid",
		    "pid", BNY_INT, (int)ent->se_pid,
		    "error", BNY_ERF, err,
		    NULL);
		errf_free(err);
	} else if (sz >= sizeof (kp)) {
		ent->se_exepath = strdup(kp.p_comm);
	}

	if (!allow_any_uid && (euid != 0) && !check_uid(euid)) {
		error("uid mismatch: peer euid %u not on allow list",
		    (u_int) euid);
		return (0);
	}

	return (1);
}
#elif defined(__APPLE__) || defined(LOCAL_PEERCRED)
/*
 * FreeBSD and macOS use the LOCAL_PEERCRED sockopt (and struct xucred).
 * macOS also has LOCAL_PEERPID, but FreeBSD doesn't seem to have an equivalent.
 */
static int
check_socket_access(int fd, socket_entry_t *ent)
{
	struct xucred *peer;
	socklen_t len;
	char pathBuf[PROC_PIDPATHINFO_MAXSIZE];
	int rc;
	uid_t euid;
#if defined(LOCAL_PEERPID)
	pid_t pid;
#endif

	peer = calloc(1, sizeof (struct xucred));
	len = sizeof (struct xucred);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, peer, &len)) {
		error("getsockopts(LOCAL_PEERCRED) %d failed: %s", fd,
		    strerror(errno));
		close(fd);
		free(peer);
		return 0;
	}
	ent->se_uid = (euid = peer->cr_uid);
	if (peer->cr_ngroups > 0)
		ent->se_gid = peer->cr_groups[0];
	free(peer);
#if defined(LOCAL_PEERPID)
	len = sizeof (pid);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0) {
		ent->se_pid = pid;
		rc = proc_pidpath(pid, pathBuf, sizeof (pathBuf));
		if (rc > 0) {
			ent->se_exepath = strdup(pathBuf);
		}
	}
#endif

	if (!allow_any_uid && (euid != 0) && !check_uid(euid)) {
		error("uid mismatch: peer euid %u not on allow list",
		    (u_int) euid);
		return (0);
	}

	return (1);
}
#elif defined(SO_PEERCRED)
/*
 * Linux et al have SO_PEERCRED and it's a struct ucred. We can also read the
 * path to the executable and cmdline out of procfs.
 */
static int
check_socket_access(int fd, socket_entry_t *ent)
{
	uint i;
	FILE *f;
	uid_t euid;
	struct ucred *peer;
	socklen_t len;
	char fn[128], ln[1024];

	peer = calloc(1, sizeof (struct ucred));
	len = sizeof (struct ucred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, peer, &len)) {
		error("getsockopts(SO_PEERCRED) %d failed: %s", fd, strerror(errno));
		free(peer);
		return (0);
	}
	ent->se_uid = (euid = peer->uid);
	ent->se_gid = peer->gid;
	ent->se_pid = peer->pid;
	free(peer);
	snprintf(fn, sizeof (fn), "/proc/%d/exe", (int)ent->se_pid);
	len = readlink(fn, ln, sizeof (ln));
	if (len > 0 && len < sizeof (ln)) {
		ent->se_exepath = strndup(ln, len);
	}
	snprintf(fn, sizeof (fn), "/proc/%d/cmdline", (int)ent->se_pid);
	f = fopen(fn, "r");
	if (f != NULL) {
		len = fread(ln, 1, sizeof (ln) - 1, f);
		fclose(f);
		for (i = 0; i < len; ++i) {
			if (ln[i] == '\0')
				ln[i] = ' ';
		}
		ent->se_exeargs = strndup(ln, len);
	}

	if (!allow_any_uid && (euid != 0) && !check_uid(euid)) {
		error("uid mismatch: peer euid %u not on allow list",
		    (u_int) euid);
		return (0);
	}

	return (1);
}
#else
static int
check_socket_access(int fd, socket_entry_t *ent)
{
	uid_t euid;
	gid_t egid;

	if (getpeereid(fd, &euid, &egid) < 0) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		return 0;
	}
	ent->se_uid = euid;
	ent->se_gid = egid;

	if (!allow_any_uid && (euid != 0) && !check_uid(euid)) {
		error("uid mismatch: peer euid %u not on allow list",
		    (u_int) euid);
		return (0);
	}

	return (1);
}
#endif

static int
handle_socket_read(u_int socknum)
{
	struct sockaddr_un sunaddr;
	socklen_t slen;
	int fd;
	socket_entry_t *ent;
	uint64_t start_time;

	slen = sizeof(sunaddr);
	fd = accept(sockets[socknum].se_fd, (struct sockaddr *)&sunaddr, &slen);
	if (fd < 0) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		return (-1);
	}

	ent = new_socket(AUTH_CONNECTION, fd);

	if (!check_socket_access(fd, ent)) {
		close_socket(ent);
		return (0);
	}

	start_time = get_pid_start_time(ent->se_pid);
	ent->se_pid_ent = find_or_make_pid_entry(ent->se_pid, start_time);
	ent->se_pid_idx = ent->se_pid_ent->pe_conn_count++;

	return (0);
}

static int
handle_conn_read(u_int socknum)
{
	char buf[1024];
	ssize_t len;
	int r;

	if ((len = read(sockets[socknum].se_fd, buf, sizeof(buf))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].se_fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].se_input, buf, len)) != 0)
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

	if (sshbuf_len(sockets[socknum].se_output) == 0)
		return 0; /* shouldn't happen */
	if ((len = write(sockets[socknum].se_fd,
	    sshbuf_ptr(sockets[socknum].se_output),
	    sshbuf_len(sockets[socknum].se_output))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].se_fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].se_output, len)) != 0)
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
			if (sockets[socknum].se_type != AUTH_SOCKET &&
			    sockets[socknum].se_type != AUTH_CONNECTION)
				continue;
			if (pfd[i].fd == sockets[socknum].se_fd)
				break;
		}
		if (socknum >= sockets_alloc) {
			error("%s: no socket for fd %d", __func__, pfd[i].fd);
			continue;
		}
		/* Process events */
		switch (sockets[socknum].se_type) {
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

void *recallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size);

#define ADD_DEADLINE(d, v)	(d) = ((d) == 0) ? (v) : MINIMUM((d), (v))

static int
prepare_poll(struct pollfd **pfdp, size_t *npfdp, int *timeoutp)
{
	struct pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	uint64_t now, deadline;

	/* Count active sockets */
	for (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].se_type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			npfd++;
			break;
		case AUTH_UNUSED:
			break;
		default:
			fatal("Unknown socket type %d", sockets[i].se_type);
			break;
		}
	}
	if (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, sizeof(struct pollfd))) == NULL)
		fatal("%s: recallocarray failed", __func__);
	*pfdp = pfd;
	*npfdp = npfd;

	for (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].se_type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			pfd[j].fd = sockets[i].se_fd;
			pfd[j].revents = 0;
			/* XXX backoff when input buffer full */
			pfd[j].events = POLLIN;
			if (sshbuf_len(sockets[i].se_output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			break;
		default:
			break;
		}
	}
	now = monotime();
	deadline = 0;

	if (txnopen)
		ADD_DEADLINE(deadline, txntimeout);
	if (parent_alive_interval != 0)
		ADD_DEADLINE(deadline, now + parent_alive_interval * 1000);
	if (card_probe_interval != 0)
		ADD_DEADLINE(deadline, card_probe_next);

	if (deadline == 0) {
		*timeoutp = -1; /* INFTIM */
	} else {
		if (deadline <= now) {
			*timeoutp = 1;
		} else {
			const uint64_t remtime = deadline - now;
			if (remtime > INT_MAX)
				*timeoutp = INT_MAX;
			else
				*timeoutp = remtime;
		}
	}
	bunyan_log(BNY_TRACE, "calculated wake-up deadline",
	    "now", BNY_UINT64, now,
	    "deadline", BNY_UINT64, deadline,
	    "poll_timeout", BNY_INT, *timeoutp,
	    NULL);
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
	exit(i);
}

/*ARGSUSED*/
static void
cleanup_handler(int sig)
{
	cleanup_socket();
	if (selk != NULL && piv_token_in_txn(selk))
		piv_txn_end(selk);
	piv_release(ks);
	piv_close(ctx);
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
		bunyan_log(BNY_INFO,
		    "Parent has died - Authentication agent exiting.", NULL);
		cleanup_socket();
		_exit(2);
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: pivy-agent [-c | -s] [-Ddim] [-a bind_address] [-E fingerprint_hash]\n"
	    "                  [-K cak] -g guid [command [arg ...]]\n"
	    "       pivy-agent [-c | -s] -k\n"
	    "\n"
	    "An ssh-agent work-alike which always contains the keys stored on\n"
	    "a PIV token and supports other PIV-related extensions.\n"
	    "\n"
	    "Options:\n"
	    "  -a bind_address       Bind to a specific UNIX domain socket\n"
	    "  -c                    Generate csh style commands on stdout\n"
	    "  -s                    Generate Bourne shell style commands\n"
	    "  -D                    Foreground mode; do not fork\n"
	    "  -d                    Debug mode\n"
	    "  -i                    Foreground + command logging\n"
	    "  -C                    Confirm new connections by running\n"
	    "                        SSH_CONFIRM or SSH_ASKPASS\n"
	    "                        (one -C = confirm only forwarded agent,\n"
	    "                         two -C = confirm all connections)\n"
	    "  -m                    Allow signing with 9D (KEY_MGMT) key\n"
	    "  -E fp_hash            Set hash algo for fingerprints\n"
	    "  -g guid               GUID or GUID prefix of PIV token to use\n"
	    "  -K cak                9E (card auth) key to authenticate PIV token\n"
	    "  -k                    Kill an already-running agent\n"
	    "  -U                    Don't check client UID (allow any uid to connect)\n"
	    "  -u username           Allow specific user to connect (can be given multiple times)\n"
#if defined(__sun)
	    "  -Z                    Don't check client zoneid (allow any zone to connect)\n"
	    "  -z zonename           Allow specific zone to connect (can be given multiple times)\n"
#endif
	    "  -S !all,9a,9e,...     Filter the key slots available through the\n"
	    "                        agent. By default all keys are available,\n"
	    "                        use '!9e' for example to disable just 9e.\n"
	    "                        !all will disable everything, allowing to\n"
	    "                        whitelist instead.\n"
	    "\n"
	    "Environment variables:\n"
	    "  SSH_ASKPASS           Path to ssh-askpass command to run to get\n"
	    "                        PIN at first use (if no PIN already known)\n"
	    "  SSH_CONFIRM           Path to a program to run to confirm that\n"
	    "                        a new client should be allowed to use the\n"
	    "                        keys in the agent. Can be 'zenity'.\n"
	    );
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

int
main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int i_flag = 0;
	int sock, ch, result, saved_errno;
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
	errf_t *err;
	struct passwd *pwd;
	boolean_t do_umask = B_TRUE;

#if !defined(__APPLE__)
	int fd;
#endif

#if defined(__sun)
	zoneid_t zid;

	zid = getzoneid();
	add_zid(zid);
#endif

	add_uid(geteuid());

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	VERIFY0(setegid(getgid()));
	VERIFY0(setgid(getgid()));

	OpenSSL_add_all_algorithms();

	bunyan_init();
	bunyan_set_name("pivy-agent");

	__progname = "pivy-agent";

	slot_ena = slotspec_alloc();
	slotspec_set_default(slot_ena);

	while ((ch = getopt(ac, av, "cCDdkisE:a:P:g:K:mZUS:u:z:")) != -1) {
		switch (ch) {
		case 'g':
			guid = parse_hex(optarg, &len);
			guid_len = len;
			if (len > 16) {
				fprintf(stderr, "error: GUID must be <=16 bytes"
				    " in length (you gave %u)\n", len);
				exit(3);
			}
			break;
		case 'U':
			allow_any_uid = B_TRUE;
			do_umask = B_FALSE;
			break;
		case 'u':
			pwd = getpwnam(optarg);
			if (pwd == NULL)
				fatal("getpwnam: user '%s' not found", optarg);
			add_uid(pwd->pw_uid);
			do_umask = B_FALSE;
			break;
#if defined(__sun)
		case 'Z':
			allow_any_zoneid = B_TRUE;
			break;
		case 'z':
			zid = getzoneidbyname(optarg);
			if (zid == -1) {
				fatal("getzoneidbyname: zone '%s' not found",
				    optarg);
			}
			add_zid(zid);
			break;
#endif
		case 'K':
			cak = sshkey_new(KEY_UNSPEC);
			VERIFY(cak != NULL);
			ptr = optarg;
			r = sshkey_read(cak, &ptr);
			if (r != 0)
				fatal("Invalid CAK key given: %d", r);
			break;
		case 'S':
			err = slotspec_parse(slot_ena, optarg);
			if (err) {
				errfx(1, err, "Invalid slot spec (-S): %s",
				    optarg);
			}
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
		case 'C':
			if (confirm_mode == C_FORWARDED)
				confirm_mode = C_CONNECTION;
			else
				confirm_mode = C_FORWARDED;
			break;
		case 'k':
			k_flag++;
			break;
		case 'P':
			fatal("pkcs11 options not supported");
			break;
		case 'm':
			sign_9d = B_TRUE;
			break;
		case 's':
			if (c_flag)
				usage();
			s_flag++;
			break;
		case 'd':
			d_flag++;
			break;
		case 'D':
			if (d_flag || D_flag)
				usage();
			D_flag++;
			break;
		case 'i':
			i_flag++;
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
		snprintf(socket_name, sizeof socket_name, "%s/agent.%ld",
		    socket_dir, (long)parent_pid);
	} else {
		/* Try to use specified agent socket */
		socket_dir[0] = '\0';
		strlcpy(socket_name, agentsocket, sizeof socket_name);
	}

	if (do_umask)
		prev_mask = umask(0177);
	sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
	if (sock < 0) {
		/* XXX - unix_listener() calls error() not perror() */
		*socket_name = '\0'; /* Don't unlink any existing file */
		cleanup_exit(1);
	}
	if (do_umask)
		umask(prev_mask);

	if (d_flag) {
		ssh_dbglevel = BNY_TRACE;
		bunyan_set_level(BNY_TRACE);
	} else if (D_flag) {
		ssh_dbglevel = BNY_DEBUG;
		bunyan_set_level(BNY_DEBUG);
	} else if (i_flag) {
		ssh_dbglevel = BNY_INFO;
		bunyan_set_level(BNY_INFO);
	}

	if (d_flag >= 2) {
		piv_full_apdu_debug = B_TRUE;
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	if (D_flag || d_flag || i_flag) {
		format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
		    SSH_AUTHSOCKET_ENV_NAME);
		printf("echo Agent pid %ld;\n", (long)parent_pid);
		fflush(stdout);
		goto skip;
	}
#if defined(__APPLE__)
	ssh_dbglevel = BNY_INFO;
	bunyan_set_level(BNY_INFO);
	if (ac != 0) {
		bunyan_log(BNY_FATAL, "OSX does not support fork() inside "
		    "applications which use smartcards, and you have "
		    "specified a command to run. It is not possible to "
		    "execute it and remain in the foreground", NULL);
		exit(1);
	}
	bunyan_log(BNY_WARN, "OSX does not support fork() inside applications "
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
	ssh_dbglevel = BNY_WARN;
	bunyan_set_level(BNY_WARN);

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
		bunyan_log(BNY_WARN, "mlockall() failed, sensitive data (e.g. PIN) "
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
		bunyan_log(BNY_WARN, "madvice(MADV_DONTDUMP) failed, sensitive "
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
	signal(SIGINT, (d_flag | D_flag | i_flag) ? cleanup_handler : SIG_IGN);
#endif
	signal(SIGHUP, cleanup_handler);
	signal(SIGTERM, cleanup_handler);

	ctx = piv_open();
	VERIFY(ctx != NULL);

	err = piv_establish_context(ctx, SCARD_SCOPE_SYSTEM);
	if (err && errf_caused_by(err, "ServiceError")) {
		bunyan_log(BNY_WARN, "failed to create PCSC context (ignoring)",
		    "error", BNY_ERF, err, NULL);
		errf_free(err);
	} else if (err) {
		bunyan_log(BNY_ERROR, "error setting up PCSC lib context",
		    "error", BNY_ERF, err, NULL);
		return (1);
	}

	err = agent_piv_open();
	if (err) {
		errf_free(err);
	} else {
		agent_piv_close(B_TRUE);
	}

	while (1) {
		prepare_poll(&pfd, &npfd, &timeout);
		result = poll(pfd, npfd, timeout);
		saved_errno = errno;
		if (parent_alive_interval != 0)
			check_parent_exists();
		now = monotime();
		if (card_probe_interval != 0 && now >= card_probe_next)
			probe_card();
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
