#include <string.h>
#include <minunit.h>
#include <titan-secure-volume/titan-secure-volume.h>
#include <titan-secure-volume/app.h>


void new_ramdisk (size_t len);


START_TEST (test_open0)
{
	int err;
	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];
	uint8_t buf[2048] = {0};

	tsv_read_urandom (mac_key, sizeof (mac_key));
	tsv_read_urandom (encryption_key, sizeof (encryption_key));
	tsv_close ();

	new_ramdisk (5*512);
	err = tsv_open (mac_key, encryption_key);
	mu_assert (err, "tsv_open should fail on a blank disk.");

	for (int i = 0; i < 16; ++i)
	{
		tsv_read_urandom (buf, sizeof (buf));
		mu_assert (!tsv_physical_write (0, buf, 3*512), "tsv_physical_write should not fail here.");

		err = tsv_open (mac_key, encryption_key);
		mu_assert (err, "tsv_open should fail on a random disk.");
	}

	err = tsv_create (mac_key, encryption_key, 512, 1);
	mu_assert (!err, "tsv_create should succeed here.");

	err = tsv_open (mac_key, encryption_key);
	mu_assert (!err, "tsv_open should succeed on a valid volume.");
	mu_assert (!tsv_close (), "tsv_close should succeed here.");

	err = tsv_open (buf, encryption_key);
	mu_assert (err, "tsv_open should fail if mac_key is wrong.");

	err = tsv_open (mac_key, buf);
	mu_assert (err, "tsv_open should fail if encryption_key is wrong.");
}
END_TEST


char *test_open (void)
{
	mu_run_test (test_open0);

	return 0;
}
