#include <string.h>
#include <minunit.h>
#include <titan_secure_volume/titan_secure_volume.h>
#include <titan_secure_volume/bsp.h>


void new_ramdisk (size_t len);


START_TEST (test_create0)
{
	int err;
	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];

	tsv_read_urandom (mac_key, sizeof (mac_key));
	tsv_read_urandom (encryption_key, sizeof (encryption_key));
	tsv_close ();

	new_ramdisk (3*512);
	err = tsv_create (mac_key, encryption_key, 0, 64);
	mu_assert (err, "tsv_create should fail if sector_size is 0.");

	err = tsv_create (mac_key, encryption_key, 512, 0);
	mu_assert (!err, "tsv_create should not fail if sector_count is 0.");

	err = tsv_create (mac_key, encryption_key, 1033, 64);
	mu_assert (err, "tsv_create should fail if sector_size is not a multiple of the encryption block.");

	err = tsv_create (mac_key, encryption_key, 3, 64);
	mu_assert (err, "tsv_create should fail if sector_size is too small.");

	for (int i = 0; i < 3*512; ++i)
	{
		new_ramdisk (i);

		err = tsv_create (mac_key, encryption_key, 512, 1);
		mu_assert (err, "tsv_create should fail if the physical volume is too small.");
	}

	new_ramdisk (5*512);
	err = tsv_create (mac_key, encryption_key, 512, 1);
	mu_assert (!err, "tsv_create should succeed if the physical volume is big enough.");
}
END_TEST


char *test_create (void)
{
	mu_run_test (test_create0);

	return 0;
}
