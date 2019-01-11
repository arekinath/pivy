/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_PIV_H)
#define _PIV_H

#include <stdint.h>
#include <assert.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "erf.h"
#include "libssh/digest.h"

extern boolean_t piv_full_apdu_debug;

enum iso_class {
	CLA_ISO = 0x00,
	CLA_CHAIN = 0x10
};

enum iso_sel_p1 {
	SEL_APP_AID = 0x04
};

enum iso_ins {
	/* Standard commands from ISO7816-4 */
	INS_SELECT = 0xA4,
	INS_GET_DATA = 0xCB,
	INS_VERIFY = 0x20,
	INS_CHANGE_PIN = 0x24,
	INS_RESET_PIN = 0x2C,
	INS_GEN_AUTH = 0x87,
	INS_PUT_DATA = 0xDB,
	INS_GEN_ASYM = 0x47,
	INS_CONTINUE = 0xC0,

	/* YubicoPIV specific */
	INS_SET_MGMT = 0xFF,
	INS_IMPORT_ASYM = 0xFE,
	INS_GET_VER = 0xFD,
	INS_SET_PIN_RETRIES = 0xFA,
	INS_GET_SERIAL = 0xF8,
	INS_ATTEST = 0xF9,
};

enum iso_sw {
	SW_NO_ERROR = 0x9000,
	SW_FUNC_NOT_SUPPORTED = 0x6A81,
	SW_CONDITIONS_NOT_SATISFIED = 0x6985,
	SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982,
	SW_BYTES_REMAINING_00 = 0x6100,
	SW_WARNING_NO_CHANGE_00 = 0x6200,
	SW_WARNING_EOF = 0x6282,
	SW_WARNING_00 = 0x6300,
	SW_FILE_NOT_FOUND = 0x6A82,
	SW_INCORRECT_PIN = 0x63C0,
	SW_INCORRECT_P1P2 = 0x6A86,
	SW_WRONG_DATA = 0x6A80,
	SW_OUT_OF_MEMORY = 0x6A84,
	SW_WRONG_LENGTH = 0x6700,
	SW_INS_NOT_SUP = 0x6D00,
};

enum piv_sel_tag {
	PIV_TAG_APT = 0x61,
	PIV_TAG_AID = 0x4F,
	PIV_TAG_AUTHORITY = 0x79,
	PIV_TAG_APP_LABEL = 0x50,
	PIV_TAG_URI = 0x5F50,
	PIV_TAG_ALGS = 0xAC,
};

enum piv_tags {
	PIV_TAG_CARDCAP = 0x5FC107,
	PIV_TAG_CHUID = 0x5FC102,
	PIV_TAG_SECOBJ = 0x5FC106,
	PIV_TAG_KEYHIST = 0x5FC10C,
	PIV_TAG_DISCOV = 0x7E,
	PIV_TAG_CERT_9A = 0x5FC105,
	PIV_TAG_CERT_9C = 0x5FC10A,
	PIV_TAG_CERT_9D = 0x5FC10B,
	PIV_TAG_CERT_9E = 0x5FC101,

	PIV_TAG_CERT_82 = 0x5FC10D,	/* First retired slot */
	PIV_TAG_CERT_95 = 0x5FC120,	/* Last retired slot */

	PIV_TAG_CERT_YK_ATTESTATION = 0x5FFF01,
};

enum gen_auth_tag {
	GA_TAG_WITNESS = 0x80,
	GA_TAG_CHALLENGE = 0x81,
	GA_TAG_RESPONSE = 0x82,
	GA_TAG_EXP = 0x85,
};

enum piv_alg {
	PIV_ALG_3DES = 0x03,
	PIV_ALG_RSA1024 = 0x06,
	PIV_ALG_RSA2048 = 0x07,
	PIV_ALG_AES128 = 0x08,
	PIV_ALG_AES192 = 0x0A,
	PIV_ALG_AES256 = 0x0C,
	PIV_ALG_ECCP256 = 0x11,
	PIV_ALG_ECCP384 = 0x14,

	/*
	 * Proprietary hack for Javacards running PivApplet -- they don't
	 * support bare ECDSA so instead we have to give them the full input
	 * data and they hash it on the card.
	 */
	PIV_ALG_ECCP256_SHA1 = 0xf0,
	PIV_ALG_ECCP256_SHA256 = 0xf1,
};

enum piv_cert_comp {
	PIV_COMP_GZIP = 1,
	PIV_COMP_NONE = 0,
};

enum piv_certinfo_flags {
	PIV_CI_X509 = (1 << 2),
	PIV_CI_COMPTYPE = 0x03,
};

enum piv_pin {
	PIV_PIN = 0x80,
	PIV_GLOBAL_PIN = 0x00,
	PIV_PUK = 0x81,
	/* We don't really support these yet. */
	PIV_OCC = 0x96,
	PIV_OCC2 = 0x97,
	PIV_PAIRING = 0x98
};

enum piv_slotid {
	PIV_SLOT_9A = 0x9A,
	PIV_SLOT_9B = 0x9B,
	PIV_SLOT_9C = 0x9C,
	PIV_SLOT_9D = 0x9D,
	PIV_SLOT_9E = 0x9E,

	PIV_SLOT_82 = 0x82,
	PIV_SLOT_95 = 0x95,

	PIV_SLOT_F9 = 0xF9,

	PIV_SLOT_PIV_AUTH = PIV_SLOT_9A,
	PIV_SLOT_ADMIN = PIV_SLOT_9B,
	PIV_SLOT_SIGNATURE = PIV_SLOT_9C,
	PIV_SLOT_KEY_MGMT = PIV_SLOT_9D,
	PIV_SLOT_CARD_AUTH = PIV_SLOT_9E,

	PIV_SLOT_RETIRED_1 = PIV_SLOT_82,
	PIV_SLOT_RETIRED_20 = PIV_SLOT_95,

	PIV_SLOT_YK_ATTESTATION = PIV_SLOT_F9,
};

enum ykpiv_pin_policy {
	YKPIV_PIN_DEFAULT = 0x00,
	YKPIV_PIN_NEVER = 0x01,
	YKPIV_PIN_ONCE = 0x02,
	YKPIV_PIN_ALWAYS = 0x03,
};

enum ykpiv_touch_policy {
	YKPIV_TOUCH_DEFAULT = 0x00,
	YKPIV_TOUCH_NEVER = 0x01,
	YKPIV_TOUCH_ALWAYS = 0x02,
	YKPIV_TOUCH_CACHED = 0x03,
};

struct apdubuf;
struct apdu;
struct piv_slot;
struct piv_token;
struct piv_ecdh_box;

#define	GUID_LEN	16

const char *piv_token_rdrname(const struct piv_token *token);

const uint8_t *piv_token_fascn(const struct piv_token *token, size_t *len);
const uint8_t *piv_token_guid(const struct piv_token *token);
const char *piv_token_guid_hex(const struct piv_token *token);
const uint8_t *piv_token_chuuid(const struct piv_token *token);
const uint8_t *piv_token_expiry(const struct piv_token *token, size_t *len);
size_t piv_token_nalgs(const struct piv_token *token);
enum piv_alg piv_token_alg(const struct piv_token *token, size_t idx);

boolean_t piv_token_has_chuid(const struct piv_token *token);
boolean_t piv_token_has_signed_chuid(const struct piv_token *token);

enum piv_pin piv_token_default_auth(const struct piv_token *token);
boolean_t piv_token_has_auth(const struct piv_token *token, enum piv_pin auth);

boolean_t piv_token_has_vci(const struct piv_token *token);

uint piv_token_keyhistory_oncard(const struct piv_token *token);
uint piv_token_keyhistory_offcard(const struct piv_token *token);
const char *piv_token_offcard_url(const struct piv_token *token);

boolean_t piv_token_is_ykpiv(const struct piv_token *token);
const uint8_t *ykpiv_token_version(const struct piv_token *token);
int ykpiv_version_compare(const struct piv_token *token, uint8_t major,
    uint8_t minor, uint8_t patch);
boolean_t ykpiv_token_has_serial(const struct piv_token *token);
uint32_t ykpiv_token_serial(const struct piv_token *token);

/*
 * Enumerates all PIV tokens attached to the given SCARDCONTEXT.
 *
 * Errors:
 *  - PCSCError: a PCSC call failed in a way that is not retryable
 */
erf_t *piv_enumerate(SCARDCONTEXT ctx, struct piv_token **tokens);

erf_t *piv_find(SCARDCONTEXT ctx, const uint8_t *guid, size_t guidlen,
    struct piv_token **token);

struct piv_token *piv_token_next(struct piv_token *token);

/*
 * Releases a list of tokens acquired from piv_enumerate or a token from
 * piv_find.
 */
void piv_release(struct piv_token *pk);

/*
 * Gets a reference to a particular key/cert slot on the card. This must have
 * been enumerated using piv_read_cert, or else this will return NULL.
 */
struct piv_slot *piv_get_slot(struct piv_token *tk, enum piv_slotid slotid);

struct piv_slot *piv_token_slots(struct piv_token *tk);
struct piv_slot *piv_next_slot(struct piv_slot *slot);

/*
 * Forces the enumeration of a slot which doesn't have a valid certificate on
 * the card. This can useful to ask the card for a signature from a particular
 * slot even though no certificate has been written there yet.
 */
struct piv_slot *piv_force_slot(struct piv_token *tk, enum piv_slotid slotid,
   enum piv_alg alg);

enum piv_slotid piv_slot_id(const struct piv_slot *slot);
enum piv_alg piv_slot_alg(const struct piv_slot *slot);
X509 *piv_slot_cert(const struct piv_slot *slot);
const char *piv_slot_subject(const struct piv_slot *slot);
struct sshkey *piv_slot_pubkey(const struct piv_slot *slot);

/* Low-level APDU access */
struct apdu *piv_apdu_make(enum iso_class cls, enum iso_ins ins, uint8_t p1,
    uint8_t p2);
void piv_apdu_set_cmd(struct apdu *apdu, const uint8_t *data, size_t len);
uint16_t piv_apdu_sw(const struct apdu *apdu);
const uint8_t *piv_apdu_get_reply(const struct apdu *apdu, size_t *len);
void piv_apdu_free(struct apdu *pdu);

erf_t *piv_apdu_transceive(struct piv_token *pk, struct apdu *pdu);
erf_t *piv_apdu_transceive_chain(struct piv_token *pk, struct apdu *apdu);

/*
 * Begins a new transaction on the card. Needs to be called before any
 * interaction with the card is possible.
 *
 * Errors:
 *  - IOError: general communication failure
 */
erf_t *piv_txn_begin(struct piv_token *key);

/*
 * Ends a transaction.
 */
void piv_txn_end(struct piv_token *key);

/*
 * Selects the PIV applet on the card. You should run this first in each
 * txn to prepare the card for other PIV commands.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - InvalidDataError: device returned invalid or unsupported payload to
 *                      select command
 *  - NotFoundError: PIV applet not found on card
 */
erf_t *piv_select(struct piv_token *tk);

/*
 * Reads the certificate in a given slot on the card, and updates the list
 * of struct piv_slots with info about it.
 *
 * This is required before commands that require a slot reference can be used
 * (e.g. piv_sign, piv_ecdh).
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - NotFoundError: no key/cert is present in this slot
 *  - NotSupportedError: card does not support the use of this slot
 *  - PermissionError: the cert in this slot requires either using a contact
 *                     interface (and the card is connected contactless), or
 *                     requires a PIN
 *  - InvalidDataError: device returned an invalid payload or unparseable
 *                      certificate
 *  - APDUError: card rejected the request (e.g because applet not selected)
 */
erf_t *piv_read_cert(struct piv_token *tk, enum piv_slotid slotid);
/*
 * Attempts to read certificates in all supported PIV slots on the card, by
 * calling piv_read_cert repeatedly. Ignores ENOENT and ENOTSUP errors. Any
 * other error will return early and may not try all slots.
 */
erf_t *piv_read_all_certs(struct piv_token *tk);

/*
 * Authenticates as the card administrator using a 3DES key.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - NotFoundError: the card has no 3DES admin key
 *  - NotSupportedError: the card does not support 3DES admin auth
 *  - InvalidDataError: the card returned unparseable data
 *  - PermissionError: the key was invalid or admin auth not allowed through
 *                     this interface (e.g. contactless)
 *  - APDUError: the card rejected the command
 */
erf_t *piv_auth_admin(struct piv_token *tk, const uint8_t *key, size_t keylen);

/*
 * YubicoPIV-specific: changes the 3DES card administrator key.
 *
 * Errors:
 *  - ArgumentError: tk is not YubicoPIV-compatible or touchpolicy is
 *                   unsupported on this version of YubicoPIV
 *  - IOError: general card communication failure
 *  - PermissionError: must call piv_auth_admin() first
 *  - APDUError: the card rejected the command
 */
erf_t *ykpiv_set_admin(struct piv_token *tk, const uint8_t *key, size_t keylen,
    enum ykpiv_touch_policy touchpolicy);

/*
 * Generates a new asymmetric private key in a slot on the token, and returns
 * the public key.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - ArgumentError: algorithm or slot ID not supported
 *  - PermissionError: the card requires admin authentication before generating
 *                     keys
 *  - InvalidDataError: the card returned invalid data which was unparseable
 *                      or unsafe to use (e.g. bad EC public point)
 *  - APDUError: the card rejected the command
 */
erf_t *piv_generate(struct piv_token *tk, enum piv_slotid slotid,
    enum piv_alg alg, struct sshkey **pubkey);

/*
 * Writes the key history object of the card with the given counts of on-
 * and off-card certs and a URL for retrieving off-card certificates.
 *
 * You should use this after generating a key in one of the key history
 * slots.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - ArgumentError: counts are too large, or offcard > 0 && offcard_url == NULL
 *  - PermissionError: the card requires admin authentication before writing
 *  - APDUError: the card rejected the command
 */
erf_t *piv_write_keyhistory(struct piv_token *tk, uint oncard, uint offcard,
    const char *offcard_url);

/*
 * YubicoPIV specific: generates a new asymmetric private key in a slot on the
 * token, and returns the public key in the same manner as piv_generate(), but
 * takes two extra arguments for the PIN and Touch policy that can be set with
 * YubicoPIV.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - ArgumentError: algorithm or slot ID not supported, card is not YubicoPIV
 *                   or version does not support given policies
 *  - PermissionError: the card requires admin authentication before generating
 *                     keys
 *  - InvalidDataError: the card returned invalid data which was unparseable
 *                      or unsafe to use (e.g. bad EC public point)
 *  - APDUError: the card rejected the command
 */
erf_t *ykpiv_generate(struct piv_token *tk, enum piv_slotid slotid,
    enum piv_alg alg, enum ykpiv_pin_policy pinpolicy,
    enum ykpiv_touch_policy touchpolicy, struct sshkey **pubkey);

/*
 * Loads a certificate for a given slot on the token.
 *
 * "flags" should include bits from enum piv_certinfo_flags (and piv_cert_comp).
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - DeviceOutOfMemoryError: certificate is too large to fit on card
 *  - EPERM: admin authentication required to write a cert
 *  - ENOENT: slot unsupported
 *  - EINVAL: other card error
 */
erf_t *piv_write_cert(struct piv_token *tk, enum piv_slotid slotid,
    const uint8_t *data, size_t datalen, uint flags);

/*
 * Tries to unlock the PIV token using a PIN code.
 *
 * The "pin" argument should be a NULL-terminated ASCII numeric string of the
 * PIN to use. Max length is 8 digits.
 *
 * The boolean "canskip" argument is used to indicate whether PIN entry should
 * be skipped if the PIN has already been entered (we use an empty VERIFY
 * command to check the security status). This should be to B_FALSE before
 * using "PIN Always" slots like the 9C Digital Signature slot.
 *
 * If the argument "retries" is given, then it will be read to determine a
 * minimum number of remaining attempts to assert are possible before trying to
 * unlock: if less than "*retries" attempts are remaining, we will not attempt
 * to unlock and will return EAGAIN.
 *
 * If EACCES is returned, then "retries" will also be written with the new
 * remaining attempts count.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - APDUError: the card rejected the command (e.g. because applet not
 *               selected)
 *  - MinRetriesError: the PIN has a remaining retries count that is too low
 *                     when compared with input value of "retries"
 *  - NotSupportedError: if pin was given as NULL to do a retry counter check
 *                       and the card does not support this form of the
 *                       command
 *  - PermissionError: the PIN code was incorrect. If non-NULL, the "retries"
 *                     argument will be written with the number of attempts
 *                     remaining before the card locks itself (and potentially
 *                     erases keys)
 */
erf_t *piv_verify_pin(struct piv_token *tk, enum piv_pin type, const char *pin,
    uint *retries, boolean_t canskip);

/*
 * Changes the PIV PIN on a token.
 *
 * The "pin" and "newpin" arguments should be a NULL-terminated ASCII numeric
 * string of the PIN to use. Max length is 10 digits.
 *
 * Errors:
 *  - EIO: general card communication failure
 *  - EINVAL: the card rejected the command (e.g. because applet not selected)
 *  - EACCES: the old PIN code was incorrect.
 */
erf_t *piv_change_pin(struct piv_token *tk, enum piv_pin type, const char *pin,
    const char *newpin);

/*
 * Resets the PIV PIN on a token using the PUK.
 *
 * The "puk" and "newpin" arguments should be a NULL-terminated ASCII numeric
 * string of the PIN to use. Max length is 10 digits.
 *
 * Errors:
 *  - EIO: general card communication failure
 *  - EINVAL: the card rejected the command (e.g. because applet not selected)
 *  - EACCES: the PUK was incorrect.
 */
erf_t *piv_reset_pin(struct piv_token *tk, enum piv_pin type, const char *puk,
    const char *newpin);

/*
 * YubicoPIV only: changes the maximum number of retries for the PIN and PUK.
 * This also resets both PIN and PUK to their default values. To execute it
 * you must have called both piv_auth_admin() and piv_verify_pin() in this
 * transaction.
 *
 * Errors:
 *  - EIO: general card communication failure
 *  - EINVAL: the card rejected the command (e.g. because applet not selected)
 *            or the card does not support YubicoPIV extensions
 *  - EPERM: the necessary auth has not been done before calling
 *            (piv_auth_admin() and piv_verify_pin()).
 */
erf_t *ykpiv_set_pin_retries(struct piv_token *tk, uint pintries, uint puktries);

/*
 * Authenticates a PIV key slot by matching its public key against the given
 * public key, and then asking it to sign randomly generated data to validate
 * that the key does match.
 *
 * Errors:
 *  - IOError: general card communication failure
 *  - APDUError: the card rejected the command (e.g. because applet not selected)
 *  - PermissionError: the key slot in question is locked
 *  - NotSupportedError: the card returned a GEN_AUTH payload type that isn't
 *                       supported
 *  - KeyAuthError: the key validation failed (either because it doesn't match
 *                  the provided pubkey, or because the signature did not
 *                  validate)
 */
erf_t *piv_auth_key(struct piv_token *tk, struct piv_slot *slot,
    struct sshkey *pubkey);

/*
 * Requests an attestation certificate.
 *
 * Errors:
 *  - EIO: general card communication failure
 *  - EINVAL: the card rejected the command (e.g. because applet not selected,
 *            or the command is unsupported)
 */
erf_t *ykpiv_attest(struct piv_token *tk, struct piv_slot *slot,
    uint8_t **data, size_t *len);

/*
 * Signs a payload using a private key stored on the card.
 *
 * "data" must contain "datalen" bytes of payload that will be signed.
 *
 * "hashalgo" will be written with the SSH digest ID of the hash algorithm that
 * was used. It can also be filled out with a desired hash algorithm before
 * calling (this will probably only work with RSA). We might not be able to give
 * you the algo you asked for (you will need to check it on return).
 *
 * "signature" will be written with a pointer to a buffer "siglen" bytes long
 * containing the output signature in ASN.1/X509 format. It should be released
 * with free().
 *
 * Errors:
 *   - IOError: general card communication failure
 *   - PermissionError: the key slot in question is locked and cannot be used.
 *                      You might need to unlock the card with piv_verify_pin.
 *   - APDUError: the card rejected the command (e.g. because applet not selected)
 *   - InvalidDataError: the card returned unparseable or invalid payloads
 *   - NotFoundError: the given slot has no key in it or is not supported by
 *                    the card
 *   - NotSupportedError: algorithm or slot is not supported
 */
erf_t *piv_sign(struct piv_token *tk, struct piv_slot *slot,
    const uint8_t *data, size_t datalen, enum sshdigest_types *hashalgo,
    uint8_t **signature, size_t *siglen);
erf_t *piv_sign_prehash(struct piv_token *tk, struct piv_slot *slot,
    const uint8_t *hash, size_t hashlen, uint8_t **signature, size_t *siglen);

/*
 * Performs an ECDH key derivation between the private key on the token and
 * the given EC public key.
 *
 * "pubkey" must point at an EC public key.
 *
 * "secret" will be written with a pointer to a buffer "seclen" bytes long
 * containing the output shared secret. It should be released with freezero().
 *
 * Errors:
 *   - EIO: general card communication failure
 *   - EPERM: the key slot in question is locked and cannot be used. You might
 *            need to unlock the card with piv_verify_pin.
 *   - EINVAL: the card rejected the command (e.g. because applet not selected)
 *   - ENOTSUP: the card returned a GEN_AUTH payload type that isn't supported
 */
erf_t *piv_ecdh(struct piv_token *tk, struct piv_slot *slot,
    struct sshkey *pubkey, uint8_t **secret, size_t *seclen);

struct piv_ecdh_box *piv_box_new(void);
struct piv_ecdh_box *piv_box_clone(const struct piv_ecdh_box *box);
int piv_box_set_data(struct piv_ecdh_box *box, const uint8_t *data, size_t len);
int piv_box_set_datab(struct piv_ecdh_box *box, struct sshbuf *buf);
erf_t *piv_box_seal(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box);
erf_t *piv_box_seal_offline(struct sshkey *pubk, struct piv_ecdh_box *box);
int piv_box_to_binary(struct piv_ecdh_box *box, uint8_t **output, size_t *len);

boolean_t piv_box_has_guidslot(const struct piv_ecdh_box *box);
const uint8_t *piv_box_guid(const struct piv_ecdh_box *box);
enum piv_slotid piv_box_slot(const struct piv_ecdh_box *box);
struct sshkey *piv_box_pubkey(const struct piv_ecdh_box *box);
struct sshkey *piv_box_ephem_pubkey(const struct piv_ecdh_box *box);
int piv_box_copy_pubkey(const struct piv_ecdh_box *box, struct sshkey **tgt);
const char *piv_box_cipher(const struct piv_ecdh_box *box);
const char *piv_box_kdf(const struct piv_ecdh_box *box);
size_t piv_box_encsize(const struct piv_ecdh_box *box);

void piv_box_set_guid(struct piv_ecdh_box *box, const uint8_t *guid,
    size_t len);
void piv_box_set_slot(struct piv_ecdh_box *box, enum piv_slotid slot);

erf_t *piv_box_from_binary(const uint8_t *input, size_t len,
    struct piv_ecdh_box **box);
erf_t *piv_box_find_token(struct piv_token *tks, struct piv_ecdh_box *box,
    struct piv_token **tk, struct piv_slot **slot);
erf_t *piv_box_open(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box);
erf_t *piv_box_open_offline(struct sshkey *privkey, struct piv_ecdh_box *box);
int piv_box_take_data(struct piv_ecdh_box *box, uint8_t **data, size_t *len);
int piv_box_take_datab(struct piv_ecdh_box *box, struct sshbuf **buf);
void piv_box_free(struct piv_ecdh_box *box);

int sshbuf_put_piv_box(struct sshbuf *buf, struct piv_ecdh_box *box);
erf_t *sshbuf_get_piv_box(struct sshbuf *buf, struct piv_ecdh_box **box);

erf_t *piv_write_file(struct piv_token *pt, uint tag,
    const uint8_t *data, size_t len);
erf_t *piv_read_file(struct piv_token *pt, uint tag, uint8_t **data,
    size_t *len);

#endif
