/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, the University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <strings.h>
#include <limits.h>
#include <err.h>
#include <fcntl.h>

#include "debug.h"

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include "debug.h"
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <sys/un.h>
#include <sys/socket.h>

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/authfd.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tlv.h"
#include "errf.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include <pwd.h>
#include <dirent.h>

#define	PAM_SM_AUTH
#include <security/pam_modules.h>

#define	PIVY_AGENT_ENV_DIR	"%s/.config/pivy-agent"
#define	PIVY_AGENT_ENV_FILE	"%s/.config/pivy-agent/%s"
#define	PIVY_AGENT_SOCKET	"%s/piv-ssh-%s.socket"
#define	SSH_AUTH_KEYS		"%s/.ssh/authorized_keys"

struct keylist {
	struct sshkey *kl_key;
	char *kl_comment;
	struct keylist *kl_next;
};

struct tkconfig {
	struct tkconfig *tkc_next;
	char *tkc_source;
	char *tkc_sockpath;
	char *tkc_guidhex;
	struct sshkey *tkc_cak;
};

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
		return ("Password");
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

static int
get_agent_socket(const char *authsocket, int *fdp)
{
	int sock, oerrno;
	struct sockaddr_un sunaddr;

	if (fdp != NULL)
		*fdp = -1;

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, sizeof(sunaddr.sun_path));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
	if (fdp != NULL)
		*fdp = sock;
	else
		close(sock);
	return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *env;
	const struct passwd *pwent;
	int res = PAM_AUTHINFO_UNAVAIL;
	int rc;
	struct piv_ctx *ctx;
	struct piv_token *tokens = NULL, *token;
	struct keylist *keys = NULL, *keyle, *nkeyle;
	struct tkconfig *tkcs = NULL, *tkc, *ntkc;
	char *akpath = NULL, *lbuf = NULL, *cp, *spath = NULL, *rdir = NULL;
	char *pin = NULL;
	size_t lsz;
	struct dirent *de;
	struct piv_slot *slot;
	DIR *d = NULL;
	FILE *f = NULL;
	errf_t *err = NULL;
	int fd;

	if ((res = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (res);

	pwent = getpwnam(user);
	if (pwent == NULL)
		return (PAM_AUTHINFO_UNAVAIL);

	ctx = piv_open();
	if (ctx == NULL)
		return (PAM_AUTHINFO_UNAVAIL);
	err = piv_establish_context(ctx, SCARD_SCOPE_SYSTEM);
	if (err) {
		errf_free(err);
		return (PAM_AUTHINFO_UNAVAIL);
	}

	akpath = malloc(PATH_MAX);
	if (akpath == NULL) {
		res = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}
	snprintf(akpath, PATH_MAX, SSH_AUTH_KEYS, pwent->pw_dir);

	f = fopen(akpath, "r");
	if (f == NULL) {
		res = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}
	while (getline(&lbuf, &lsz, f) != -1) {
		cp = lbuf;
		while (*cp == ' ' || *cp == '\t')
			++cp;
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;
		keyle = calloc(1, sizeof (struct keylist));
		if (keyle == NULL) {
			res = PAM_AUTHINFO_UNAVAIL;
			goto out;
		}
		keyle->kl_next = keys;
		keyle->kl_key = sshkey_new(KEY_UNSPEC);
		if (sshkey_read(keyle->kl_key, &cp) != 0) {
			sshkey_free(keyle->kl_key);
			free(keyle);
			continue;
		}
		while (*cp == ' ' || *cp == '\t')
			++cp;
		cp[strlen(cp) - 1] = '\0';
		keyle->kl_comment = strdup(cp);
		keys = keyle;
	}
	fclose(f);
	f = NULL;

	if (keys == NULL) {
		res = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	spath = malloc(PATH_MAX);
	if (spath == NULL) {
		res = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	env = getenv("XDG_RUNTIME_DIR");
	if (env != NULL) {
		rdir = strdup(env);
	} else {
		rdir = malloc(PATH_MAX);
		snprintf(rdir, PATH_MAX, "/run/user/%d", pwent->pw_uid);
	}

	snprintf(akpath, PATH_MAX, PIVY_AGENT_ENV_DIR, pwent->pw_dir);
	d = opendir(akpath);
	if (d != NULL) {
		while ((de = readdir(d)) != NULL) {
			snprintf(akpath, PATH_MAX, PIVY_AGENT_ENV_FILE,
			    pwent->pw_dir, de->d_name);
			f = fopen(akpath, "r");
			if (f == NULL)
				continue;
			tkc = calloc(1, sizeof (struct tkconfig));
			if (tkc == NULL) {
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}
			tkc->tkc_next = tkcs;
			tkc->tkc_source = strdup(akpath);
			snprintf(spath, PATH_MAX, PIVY_AGENT_SOCKET,
			    rdir, de->d_name);
			tkc->tkc_sockpath = strdup(spath);
			while (getline(&lbuf, &lsz, f) != -1) {
				if (strncmp(lbuf, "PIV_AGENT_GUID=", 15) == 0) {
					cp = lbuf + 15;
					cp[strlen(cp) - 1] = '\0';
					tkc->tkc_guidhex = strdup(cp);
				} else if (strncmp(lbuf, "PIV_AGENT_CAK=", 14)
				    == 0) {
					tkc->tkc_cak = sshkey_new(KEY_UNSPEC);
					cp = lbuf + 14;
					while (*cp == ' ' || *cp == '"')
						++cp;
					while (cp[strlen(cp) - 1] == '\n')
						cp[strlen(cp) - 1] = '\0';
					while (cp[strlen(cp) - 1] == '"')
						cp[strlen(cp) - 1] = '\0';
					if (sshkey_read(tkc->tkc_cak, &cp) != 0) {
						sshkey_free(tkc->tkc_cak);
						tkc->tkc_cak = NULL;
						continue;
					}
				}
			}
			if (tkc->tkc_guidhex == NULL || tkc->tkc_cak == NULL) {
				sshkey_free(tkc->tkc_cak);
				free(tkc->tkc_guidhex);
				free(tkc->tkc_source);
				free(tkc);
				continue;
			}
			tkcs = tkc;
			fclose(f);
			f = NULL;
		}
		closedir(d);
		d = NULL;
	}

	err = piv_enumerate(ctx, &tokens);
	if (err) {
		errf_free(err);
		res = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	for (token = tokens; token != NULL; token = piv_token_next(token)) {
		int found = 0;

		for (tkc = tkcs; tkc != NULL; tkc = tkc->tkc_next) {
			const int cmp = strncasecmp(tkc->tkc_guidhex,
			    piv_token_guid_hex(token),
			    strlen(tkc->tkc_guidhex));
			if (cmp == 0) {
				err = piv_txn_begin(token);
				if (err) {
					errf_free(err);
					continue;
				}

				err = piv_select(token);
				if (err == NULL)
					err = piv_read_all_certs(token);
				slot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
				if (err == NULL && slot != NULL) {
					err = piv_auth_key(token, slot,
					    tkc->tkc_cak);
				}

				if (err) {
					piv_txn_end(token);
					errf_free(err);
					continue;
				}

				slot = NULL;
				while ((slot = piv_slot_next(token, slot))) {
					const struct sshkey *pubk =
					    piv_slot_pubkey(slot);
					for (keyle = keys; keyle != NULL;
					    keyle = keyle->kl_next) {
						if (sshkey_equal_public(
						    keyle->kl_key,
						    pubk)) {
							found = 1;
							break;
						}
					}
					if (found)
						break;
				}
				if (found)
					break;
				piv_txn_end(token);
			}
		}

		if (!found)
			continue;

again:
		err = piv_auth_key(token, slot, piv_slot_pubkey(slot));
		if (errf_caused_by(err, "PermissionError")) {
			uint retries = 1;
			enum piv_pin auth = piv_token_default_auth(token);
			char *prompt, *shortid;
			struct pam_conv *conv;
			struct pam_message msg;
			const struct pam_message *pmsg[1];
			struct pam_response *resp;

			errf_free(err);

			res = pam_get_item(pamh, PAM_CONV,
			    (const void **)&conv);
			if (res != PAM_SUCCESS || !conv || !conv->conv) {
				piv_txn_end(token);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			prompt = malloc(PATH_MAX);
			if (prompt == NULL) {
				piv_txn_end(token);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			shortid = piv_token_shortid(token);
			snprintf(prompt, PATH_MAX, "%s for token %s: ",
			    pin_type_to_name(auth), shortid);
			free(shortid);

			pmsg[0] = &msg;
			msg.msg = prompt;
			msg.msg_style = PAM_PROMPT_ECHO_OFF;

			res = conv->conv(1, pmsg, &resp, conv->appdata_ptr);
			free(prompt);
			if (res != PAM_SUCCESS) {
				piv_txn_end(token);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			if (!resp || !resp->resp) {
				piv_txn_end(token);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			err = piv_verify_pin(token, auth, resp->resp, &retries,
			    B_FALSE);
			if (err) {
				piv_txn_end(token);
				res = PAM_AUTH_ERR;
				goto out;
			}

			if (pin != NULL) {
				explicit_bzero(pin, strlen(pin));
				free(pin);
			}
			pin = strdup(resp->resp);

			explicit_bzero(resp->resp, strlen(resp->resp));
			free(resp->resp);
			free(resp);
			goto again;
		}
		piv_txn_end(token);

		if (err != NULL) {
			errf_free(err);
			continue;
		}

		if (pin != NULL &&
		    get_agent_socket(tkc->tkc_sockpath, &fd) == 0) {
			struct sshbuf *req;
			uint8_t code;

			req = sshbuf_new();
			if (req == NULL) {
				close(fd);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			if ((rc = sshbuf_put_u8(req,
			    SSH_AGENTC_UNLOCK))) {
				sshbuf_free(req);
				close(fd);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			if ((rc = sshbuf_put_cstring(req, pin))) {
				sshbuf_free(req);
				close(fd);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			rc = ssh_request_reply(fd, req, req);
			close(fd);
			if (rc) {
				sshbuf_free(req);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}

			if ((rc = sshbuf_get_u8(req, &code))) {
				sshbuf_free(req);
				res = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}
			sshbuf_free(req);
		}

		res = PAM_SUCCESS;
		goto out;
	}

	res = PAM_AUTHINFO_UNAVAIL;

out:
	if (f != NULL)
		fclose(f);
	if (d != NULL)
		closedir(d);
	for (keyle = keys; keyle != NULL; keyle = nkeyle) {
		nkeyle = keyle->kl_next;
		free(keyle->kl_comment);
		sshkey_free(keyle->kl_key);
		free(keyle);
	}
	for (tkc = tkcs; tkc != NULL; tkc = ntkc) {
		ntkc = tkc->tkc_next;
		free(tkc->tkc_source);
		free(tkc->tkc_guidhex);
		free(tkc->tkc_sockpath);
		sshkey_free(tkc->tkc_cak);
		free(tkc);
	}
	free(akpath);
	free(spath);
	free(lbuf);
	free(rdir);
	if (pin != NULL) {
		explicit_bzero(pin, strlen(pin));
		free(pin);
		pin = NULL;
	}
	piv_release(tokens);
	piv_close(ctx);

	return (res);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	if (flags & PAM_DELETE_CRED)
		return (PAM_SUCCESS);

	if (flags & PAM_REFRESH_CRED)
		return (PAM_SUCCESS);

	if (flags & PAM_REINITIALIZE_CRED)
		return (PAM_SUCCESS);

	if (!(flags & PAM_ESTABLISH_CRED))
		return (PAM_SERVICE_ERR);

	/* We don't do anything else currently. */
	return (PAM_SUCCESS);
}

void
cleanup_exit(int i)
{
	exit(i);
}
