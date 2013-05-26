#ifndef __LINUX_MACACHE_H
#define __LINUX_MACACHE_H

void macache_put(const char* key, char* value);
char* macache_get(const char* key);

static inline u64 mac2u64(const char* mac)
{
	return (*(u64*)mac) & 0xffffffffffff;
}

static inline void mac_setu64(char* mac, u64 mac64)
{
	*(u32*)mac = *(u32*)&mac64;
	*(u16*)(mac+4) = *(u16*)((char*)&mac64 + 4);
}


//#define __LINUX_MACACHE_H

#endif

