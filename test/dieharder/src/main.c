#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <titan_secure_volume/titan_secure_volume.h>
#include <titan_secure_volume/bsp.h>
#include <strong-arm/threefish.h>


/* TSV BSP */
uint8_t *g_ramdisk = NULL;
size_t g_ramdisk_len = 0;

void tsv_fatal_error (void)
{
	fprintf (stderr, "ERROR: TSV_FATAL_ERROR\n");
	exit (-1);
}


/* Use a fixed seed Threefish_CTR CSPRNG, so results are reproducible. */
void tsv_read_urandom (void *dst, size_t len)
{
	static uint64_t counter = 1;
	uint8_t key[64];
	uint8_t tweak[16];
	uint8_t plaintext[64];

	memset (key, 0xB5, sizeof (key));
	memset (tweak, 0xA9, sizeof (tweak));

	while (len)
	{
		size_t l = (len < 64) ? len : 64;

		memset (plaintext, 0, sizeof (plaintext));

		for (int i = 0; i < 8; ++i)
			plaintext[i] = counter >> (i * 8);

		threefish512_encrypt_block (plaintext, key, tweak, plaintext);
		counter += 1;

		memmove (dst, plaintext, l);
		dst = ((uint8_t *)dst) + l;
		len -= l;
	}
}


int tsv_physical_read (void *dst, uint64_t offset, size_t len)
{
	if (!g_ramdisk)
		return -1;

	if (!len)
		return 0;

	if (offset >= g_ramdisk_len || (g_ramdisk_len - offset) < len)
		return -1;

	memmove (dst, g_ramdisk + offset, len);

	return 0;
}


int tsv_physical_write (uint64_t offset, void const *src, size_t len)
{
	if (!g_ramdisk)
		return -1;

	if (!len)
		return 0;

	if (offset + len >= g_ramdisk_len)
	{
		g_ramdisk = realloc (g_ramdisk, offset + len);
		g_ramdisk_len = offset + len;
	}

	memmove (g_ramdisk + offset, src, len);

	return 0;
}


int main (int argc, char *argv[])
{
	int sector_size = 4096;
	int volume_size = 1 * 1024 * 1024;
	uint8_t mac_key[TSV_MAC_KEY_SIZE] = {0};
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE] = {0};
	uint8_t *buf;

	/* Fixed keys, for reproducible results */
	memset (mac_key, 0xAA, sizeof (mac_key));
	memset (encryption_key, 0xAA, sizeof (mac_key));

	if (argc == 3)
	{
		sector_size = atoi (argv[1]);
		volume_size = atoi (argv[2]);
	}

	buf = malloc (volume_size);
	memset (buf, 0, volume_size);
	g_ramdisk = malloc (1);
	g_ramdisk_len = 1;

	for (uint64_t counter = 0;; ++counter)
	{
		for (int i = 0; i < 8; ++i)
			encryption_key[i] = counter >> (i * 8);

		if (tsv_create (mac_key, encryption_key, sector_size, volume_size / sector_size))
			break;

		if (tsv_open (mac_key, encryption_key))
			break;

		/* Blank the volume, for reproducible results */
		if (tsv_write (0, buf, volume_size))
			break;

		/* Print result */
		if (fwrite (g_ramdisk, g_ramdisk_len, 1, stdout) != 1)
			break;

		if (tsv_close ())
			break;
	}

	fprintf (stderr, "ERROR\n");

	return -1;
}
