#include <linux/module.h>
#include <linux/hash.h>
#include "macache.h"

#define HASH_MAC_BITS 10
#define HASH_MAC_BUCKETS (1<<HASH_MAC_BITS)
#define HASH_MAC_BUCKET_SIZE 16
#define HASH_MAC_BUCKET_MASK (HASH_MAC_BUCKET_SIZE-1)

struct mc_record
{
	union {
		char mac_key[6];
		u64 key64;
	};
	union {
		char mac_value[6];
		u64 value64;
	};
};

static struct mc_record macache[HASH_MAC_BUCKETS][HASH_MAC_BUCKET_SIZE];

static inline u32 hash_mac(u64 mac64)
{
	return (u32)hash_64(mac64, HASH_MAC_BITS);
}

void macache_put(const char* key, char* value)
{
	int i;
	u64 key64 = mac2u64(key);
	u64 value64 = mac2u64(value);
	u32 hash = hash_mac(key64);
	struct mc_record* p = &macache[hash][0];
	struct mc_record* fap = NULL;
	
	for (i=0; i<HASH_MAC_BUCKET_SIZE; ++i, ++p)
		if (fap==NULL && p->key64==0) fap = p;
		else if (p->key64 == key64)
		{
			p->value64 = value64;
			return;
		}

	if (fap==NULL)		// no available slot found
	{					// choose a random slot by jiffies
		i = (int)(jiffies & HASH_MAC_BUCKET_MASK);
		fap = &macache[hash][i];
		fap->key64 = key64;
		fap->value64 = value64;
	}
}
EXPORT_SYMBOL(macache_put);

char* macache_get(const char* key)
{
	int i;
	u64 key64 = mac2u64(key);
	u32 hash = hash_mac(key64);
	struct mc_record* p = &macache[hash][0];

	for (i=0; i<HASH_MAC_BUCKET_SIZE; ++i, ++p)
		if (p->key64 == key64)
			return p->mac_value;

	return NULL;
}
EXPORT_SYMBOL(macache_get);

static int __init macache_init(void)
{
	memset(macache, 0, sizeof(macache));
	return 0;
}

static void __exit macache_finit(void)
{
}

module_init(macache_init);
module_exit(macache_finit);
MODULE_DESCRIPTION("MAC address cache");
MODULE_LICENSE("GPL");
