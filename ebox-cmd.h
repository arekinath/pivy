/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

/*
 * Shared utility functions for cmdline tools that use eboxes (pivy-box,
 * pivy-zfs, pivy-luks)
 */

#if !defined(_EBOX_CMD_H)
#define _EBOX_CMD_H

#include <sys/types.h>

#include "errf.h"
#include "piv.h"
#include "ebox.h"
#include "utils.h"

#include "openssh/config.h"
#include "openssh/digest.h"

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#if defined(__sun)
#include <libtecla.h>
#elif defined(__OpenBSD__)
#include <readline/readline.h>
#else
#include <editline/readline.h>
#endif

extern char *ebox_pin;
extern uint ebox_min_retries;
extern boolean_t ebox_batch;

extern struct piv_ctx *ebox_ctx;

extern const char *wordlist[];

enum ebox_exit_status {
	EXIT_OK = 0,
	EXIT_USAGE = 1,
	EXIT_ERROR = 2,
	EXIT_INTERACTIVE = 3,
	EXIT_PIN = 4,
	EXIT_PIN_LOCKED = 5,
	EXIT_ALREADY_UNLOCKED = 6,
};

enum ebox_tpl_path_seg_type {
	PATH_SEG_FIXED,
	PATH_SEG_ENV,
	PATH_SEG_TPL
};

struct ebox_tpl_path_seg {
	struct ebox_tpl_path_seg *tps_next;
	enum ebox_tpl_path_seg_type tps_type;
	union {
		char *tps_fixed;
		char *tps_env;
	};
};

struct ebox_tpl_path_ent {
	struct ebox_tpl_path_ent *tpe_next;
	char *tpe_path_tpl;
	struct ebox_tpl_path_seg *tpe_segs;
};

extern struct ebox_tpl_path_ent *ebox_tpl_path;

#define	TPL_MAX_SIZE		4096
#define	EBOX_MAX_SIZE		16384
#define	BASE64_LINE_LEN		65

char *compose_path(const struct ebox_tpl_path_seg *segs, const char *tpl);
FILE *open_tpl_file(const char *tpl, const char *mode);
char *access_tpl_file(const char *tpl, int amode);
void parse_tpl_path_env(void);
void release_context(void);

char *piv_token_shortid(struct piv_token *pk);
const char *pin_type_to_name(enum piv_pin type);
void assert_pin(struct piv_token *pk, struct piv_slot *slot,
    const char *partname, boolean_t prompt);

errf_t *read_tpl_file_err(const char *tpl, struct ebox_tpl **ptpl);
struct ebox_tpl *read_tpl_file(const char *tpl);

errf_t *interactive_select_tpl(struct ebox_tpl **ptpl);

boolean_t can_local_unlock(struct piv_ecdh_box *box);

errf_t *local_unlock_agent(struct piv_ecdh_box *box);
errf_t *local_unlock(struct piv_ecdh_box *box, struct sshkey *cak,
    const char *name);
errf_t *interactive_recovery(struct ebox_config *config, const char *what);

errf_t *interactive_unlock_ebox(struct ebox *ebox, const char *fn);

void interactive_select_local_token(struct ebox_tpl_part **ppart);

#define	Q_MAX_LEN	2048
#define	ANS_MAX_LEN	512

struct question {
	struct answer *q_ans;
	struct answer *q_lastans;
	struct answer *q_coms;
	struct answer *q_lastcom;
	void *q_priv;
	size_t q_used;
	char q_prompt[Q_MAX_LEN];
};

struct answer {
	struct answer *a_next;
	struct answer *a_prev;
	char a_key;
	void *a_priv;
	size_t a_used;
	char a_text[ANS_MAX_LEN];
};

void add_answer(struct question *q, struct answer *a);
void add_spacer(struct question *q);
void remove_answer(struct question *q, struct answer *a);
void remove_command(struct question *q, struct answer *a);
void answer_printf(struct answer *ans, const char *fmt, ...);
struct answer *make_answer(char key, const char *fmt, ...);
void add_command(struct question *q, struct answer *a);
void question_printf(struct question *q, const char *fmt, ...);
void question_free(struct question *q);
void question_prompt(struct question *q, struct answer **ansp);
void qa_term_setup(void);

void make_answer_text_for_part(struct ebox_tpl_part *part, struct answer *a);
void make_answer_text_for_config(struct ebox_tpl_config *config,
    struct answer *a);

void printwrap(FILE *stream, const char *data, size_t col);

#ifndef LINT
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))
#endif

#if defined(__sun)
char *readline(const char *prompt);
#endif

struct ans_config {
	struct ebox_config	*ac_config;
	struct answer		*ac_ans;
};

#endif
