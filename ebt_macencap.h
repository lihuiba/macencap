#ifndef __LINUX_BRIDGE_EBT_MACENCAP_H
#define __LINUX_BRIDGE_EBT_MACENCAP_H

struct ebt_macencap_info {
	struct ethhdr header;
	int target;
};

//#define __LINUX_BRIDGE_EBT_MACENCAP_H "macencap"

#endif

