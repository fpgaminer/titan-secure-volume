#include <string.h>
#include <minunit.h>
#include <titan-secure-volume/titan-secure-volume.h>
#include <titan-secure-volume/app.h>


void new_ramdisk (size_t len);


START_TEST (test_corruption0)
{
	int err;
	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];
	int volume_len = 1 * 1024 * 1024;
	uint8_t buf[4096] = {0};
	uint8_t *real_copy = malloc (volume_len);
	uint8_t *result = malloc (volume_len);

	tsv_read_urandom (mac_key, sizeof (mac_key));
	tsv_read_urandom (encryption_key, sizeof (encryption_key));
	tsv_close ();

	new_ramdisk (volume_len * 3);
	mu_assert (!tsv_create (mac_key, encryption_key, 4096, volume_len / 4096), "tsv_create should succeed in test_corruption.");
	mu_assert (!tsv_open (mac_key, encryption_key), "tsv_open should succeed in test_corruption.");

	tsv_read_urandom (real_copy, volume_len);
	err = tsv_write (0, real_copy, volume_len);
	mu_assert (!err, "tsv_write should succeed at the beginning of corruption test.");

	for (int i = 0; i < 1024; ++i)
	{
		/* Corrupt disk */
		uint32_t len, offset;

		tsv_read_urandom (&len, sizeof (len));
		tsv_read_urandom (&offset, sizeof (offset));
		len = (len % 4096) + 1;

		offset = offset % (volume_len * 3 - len);
		mu_assert (!tsv_physical_write (offset, buf, len), "tsv_physical_write should succeed in test_corruption.");

		/* Read and write back to disk to force error correction. */
		err = tsv_read (result, 0, volume_len);
		mu_assert (!err, "tsv_read should succeed in test_corruption.");

		err = tsv_write (0, result, volume_len);
		mu_assert (!err, "tsv_write should succeed in test_corruption.");
	}

	/* Final readback and verify */
	err = tsv_read (result, 0, volume_len);
	mu_assert (!err, "tsv_read should succeed in test_corruption.");

	mu_assert (!memcmp (real_copy, result, volume_len), "Volume should not become corrupted from small errors on disk.");
}
END_TEST


char *test_corruption (void)
{
	mu_run_test (test_corruption0);

	return 0;
}
