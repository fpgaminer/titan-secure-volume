#ifndef __TSV_UTIL_H__
#define __TSV_UTIL_H__

#include <stdlib.h>
#include <titan_secure_volume/bsp.h>


#ifndef MIN
	#define MIN(a,b)  (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
	#define MAX(a,b)  (((a) > (b)) ? (a) : (b))
#endif


#define RtnOnError(x) {int _xxerr; if ((_xxerr = (x))) return _xxerr;}


/* Constant Time, with respect to Length. */
/* Returns 0 if both are equal. */
static inline int __attribute__((optimize("O0"))) secure_memcmp (void const *a, void const *b, size_t len)
{
	uint8_t const *pa = (uint8_t const *)a;
	uint8_t const *pb = (uint8_t const *)b;
	uint8_t ret = 0;

	for (; len > 0; --len)
		ret |= (*(pa++)) ^ (*(pb++));

	return ret != 0;
}


/* Round (num) up to the nearest multiple of (mod). */
static inline uint32_t roundup_uint32 (uint32_t num, uint32_t mod)
{
	if (mod == 0)
		tsv_fatal_error ();

	uint32_t remainder = num % mod;
	uint32_t extra = mod - remainder;
	uint32_t result = num + extra;

	if (remainder == 0)
		return num;

	if (result < num)
		tsv_fatal_error ();  // Overflow

	return result;
}


static inline uint64_t roundup_uint64 (uint64_t num, uint64_t mod)
{
	if (mod == 0)
		tsv_fatal_error ();

	uint64_t remainder = num % mod;
	uint64_t extra = mod - remainder;
	uint64_t result = num + extra;

	if (remainder == 0)
		return num;

	if (result < num)
		tsv_fatal_error ();  // Overflow

	return result;
}

#endif
