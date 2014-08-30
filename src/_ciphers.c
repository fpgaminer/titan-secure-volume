#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strong-arm/threefish.h>
#include <strong-arm/hmac.h>
#include "basic_packing.h"
#include <titan-secure-volume/app.h>
#include "_ciphers.h"



/* These asserts should be updated if the implemented cryptography changes. */
_Static_assert (ENCRYPTION_BLOCK_SIZE == 64, "ENCRYPTION_BLOCK_SIZE does not match implemented cryptography.");
_Static_assert (TSV_ENCRYPTION_KEY_SIZE == 64, "TSV_ENCRYPTION_KEY_SIZE does not match implemented cryptography.");

void _volume_encrypt (void *dst, uint8_t const key[static TSV_ENCRYPTION_KEY_SIZE], void const *src, size_t len, uint32_t sector_num)
{
	uint8_t tweak[16] = {0};
	uint64_t block_num = 0;

	if ((len & 63) != 0)
		tsv_fatal_error ();

	// Calculate initial tweak
	pack_uint32_little (tweak, sector_num);

	// Encrypt blocks
	for (; len; len -= 64)
	{
		pack_uint64_little (tweak+8, block_num);
		threefish512_encrypt_block (dst, key, tweak, src);

		block_num += 1;
		src = ((uint8_t const *)src) + 64;
		dst = ((uint8_t *)dst) + 64;
	}
}


void _volume_decrypt (void *dst, uint8_t const key[static TSV_ENCRYPTION_KEY_SIZE], void const *src, size_t len, uint32_t sector_num)
{
	uint8_t tweak[16] = {0};
	uint64_t block_num = 0;

	if ((len & 63) != 0)
		tsv_fatal_error ();

	// Calculate initial tweak
	pack_uint32_little (tweak, sector_num);

	// Decrypt blocks
	for (; len; len -= 64)
	{
		pack_uint64_little (tweak+8, block_num);
		threefish512_decrypt_block (dst, key, tweak, src);

		block_num += 1;
		src = ((uint8_t const *)src) + 64;
		dst = ((uint8_t *)dst) + 64;
	}
}


/* HMAC-SHA-256 */
/* These asserts should be updated if the implemented cryptography changes. */
_Static_assert (TSV_MAC_KEY_SIZE == 64, "TSV_MAC_KEY_SIZE does not match implemented cryptography.");
_Static_assert (MAC_TAG_SIZE == 32, "MAC_TAG_SIZE does not match implemented cryptography.");

void _volume_mac (void *dst, uint8_t const key[static TSV_MAC_KEY_SIZE], void const *src, size_t len, uint32_t sector_num)
{
	uint8_t tmp[4];
	HMAC_STATE hmac_state;

	pack_uint32_little (tmp, sector_num);
	HMAC_partial (NULL, &hmac_state, key, TSV_MAC_KEY_SIZE, src, len, true, false);
	HMAC_partial (dst, &hmac_state, NULL, 0, tmp, sizeof (tmp), false, true);
}
