#ifndef __LINUX_BRIDGE_EBT_MSROUTE_H
#define __LINUX_BRIDGE_EBT_MSROUTE_H

struct ebt_msroute_info {
	int target;
	bool fast_forward;
};

struct msrhdr {
	struct ethhdr ethhdr;
	unsigned char h_mac3[ETH_ALEN];		// addr of the 3rd party
	__be16		NW;						// network number of the 3rd party
} __attribute__((packed));;

//#define __LINUX_BRIDGE_EBT_MSROUTE_H "msroute"

#endif

