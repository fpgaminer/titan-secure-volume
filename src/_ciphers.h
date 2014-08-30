/*
 * Private Header
 *
 * Cryptography implementation for the Titan Secure Volume code.
 * Keeping this separated allows different crypto functions to be swapped in.
 */
#ifndef __TITAN_SECURE_VOLUME_CIPHERS_H__
#define __TITAN_SECURE_VOLUME_CIPHERS_H__

#include <titan-secure-volume/titan-secure-volume.h>

/* 
 * Encryption: Threefish-512-XTS (really, just Threefish tweaked by sectornum||blocknum)
 * MAC: HMAC-SHA-256
 */

#define MAC_TAG_SIZE 32
#define ENCRYPTION_BLOCK_SIZE 64


/* Call on whole sectors, or the entire header, only.  Never encrypt sectors in pieces.
 * This function does not support an offset parameter, so it will fail if you attempt to encrypt, for example, just the middle of a sector.
 */
void _volume_encrypt (void *dst, uint8_t const key[static TSV_ENCRYPTION_KEY_SIZE], void const *src, size_t len, uint32_t sector_num);

/* See above */
void _volume_decrypt (void *dst, uint8_t const key[static TSV_ENCRYPTION_KEY_SIZE], void const *src, size_t len, uint32_t sector_num);

void _volume_mac (void *dst, uint8_t const key[static TSV_MAC_KEY_SIZE], void const *src, size_t len, uint32_t sector_num);

#endif
