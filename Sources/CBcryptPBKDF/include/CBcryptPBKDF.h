/*
 * Public interface for Keygate's vendored bcrypt_pbkdf.
 *
 * The implementation (bcrypt_pbkdf.c) and the Blowfish cipher it depends on
 * (blowfish.c / blf.h) are vendored from OpenBSD:
 *   - bcrypt_pbkdf.c  (c) 2013 Ted Unangst, ISC license
 *   - blowfish.c / blf.h  (c) 1997 Niels Provos, BSD 3-clause (no-advertising)
 * The SHA-512 preprocessing was adapted to use CommonCrypto on macOS.
 */
#ifndef KEYGATE_CBCRYPTPBKDF_H
#define KEYGATE_CBCRYPTPBKDF_H

#include <stddef.h>
#include <stdint.h>

/*
 * Derives `keylen` bytes into `key` from `pass`/`salt` using OpenSSH's
 * bcrypt_pbkdf KDF with the given round count. Returns 0 on success, -1 on
 * invalid arguments. Renamed from the OpenBSD symbol to avoid any collision.
 */
int keygate_bcrypt_pbkdf(const char *pass, size_t passlen,
                         const uint8_t *salt, size_t saltlen,
                         uint8_t *key, size_t keylen,
                         unsigned int rounds);

#endif /* KEYGATE_CBCRYPTPBKDF_H */
