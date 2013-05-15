/* ebt_macencap
 *
 * Authors:
 * Huiba Li <lihuiba@gmail.com>
 *
 *  May, 2013
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_arpreply.h>
#include <linux/netfilter_bridge/ebt_macencap.h>

#define SRC_MAC '1'
#define DES_MAC '2'
#define PROTO   '3'
#define TARGET  '4'
static struct option opts[] =
{
	{ "encap-smac" ,  required_argument, 0, SRC_MAC },
	{ "encap-dmac" ,  required_argument, 0, DES_MAC },
	{ "encap-proto" , required_argument, 0, PROTO   },
	{ "encap-target", required_argument, 0, TARGET   },
	{ 0 }
};

static void print_help()
{
	printf(
	"macencap (MAC encapsulation) target options:\n"
	" --encap-smac address           : source MAC of generated MAC header\n"
	" --encap-dmac address           : destination MAC of generated MAC header\n"
	" --encap-proto number           : protocol number (0x****) of generated MAC header\n"
	" --encap-target target          : the target of macencap (deftaul: CONTINUE)\n"
	"\n");
}

#define DEFAULT_TARGET EBT_CONTINUE

static void init(struct ebt_entry_target *target)
{
	struct ebt_macencap_info *info =
	   (struct ebt_macencap_info *)target->data;

	memset(&info->header, 0, sizeof(struct ethhdr));
	info->target = DEFAULT_TARGET;
}

static unsigned int htoi(char* s)
{
	unsigned int val=0;
	for (; /* *s!='\0' */; s++)
	{
		char d=*s;
		if (d>='0' && d<='9') d-='0';
		else if(d>='A' && d<='F') d-='A'+10;
		else if(d>='a' && d<='f') d-='a'+10;
		else break;
		//printf("%x", d);
		val = val*16 + d;
	}
	//printf("==%x\n",val);
	return val;
}

static inline int beginswith0x(char* s)
{
	return s[0]=='0' && (s[1]=='x' || s[1]=='X');
}

#define OPT_SMAC     0x01
#define OPT_DMAC     0x02
#define OPT_PROTO    0x04
#define OPT_TARGET   0x08
static int parse(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	struct ether_addr *addr;
	struct ebt_macencap_info *info =
	   (struct ebt_macencap_info *)(*target)->data;

	switch (c) {
	case SRC_MAC:
		ebt_check_option2(flags, OPT_SMAC);
		if (!(addr = ether_aton(optarg)))
			ebt_print_error2("Problem with specified --encap-smac mac");
		memcpy(info->header.h_source, addr, ETH_ALEN);
		break;
	case DES_MAC:
		ebt_check_option2(flags, OPT_DMAC);
		if (!(addr = ether_aton(optarg)))
			ebt_print_error2("Problem with specified --encap-dmac mac");
		memcpy(info->header.h_dest, addr, ETH_ALEN);
		break;
	case PROTO:
		ebt_check_option2(flags, OPT_TARGET);
		if (!beginswith0x(optarg))
			ebt_print_error2("Problem with specified --encap-proto number (0x****)");
		{
			//unsigned short proto=(unsigned short)htoi(optarg+2);
			//printf("encap-proto: 0x%04x (%d)", htons(proto), proto);
			info->header.h_proto = htons((unsigned short)htoi(optarg+2));
		}
		break;
	case TARGET:
		ebt_check_option2(flags, OPT_TARGET);
		if (FILL_TARGET(optarg, info->target))
			ebt_print_error2("Illegal --encap--target target");
		break;

	default:
		printf("parse: unknow char '%c'\n", c);
		return 0;
	}
	return 1;
}

static inline int iszeromac(unsigned char* mac)
{
	return *(int32_t*)mac==0 && *(int16_t*)(mac+4)==0;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name,
   unsigned int hookmask, unsigned int time)
{
	struct ebt_macencap_info *info =
		(struct ebt_macencap_info *)target->data;

	if (ntohs(info->header.h_proto) <= 0x0600) {
		ebt_print_error("The protocol (0x%04x) must be greater than 0x0600", 
			ntohs(info->header.h_proto));
	} else if (time == 0 && iszeromac(info->header.h_source)) {
		ebt_print_error("No source mac supplied");
	} else if (time == 0 && iszeromac(info->header.h_dest)) {
		ebt_print_error("No destination mac supplied");
	} else if (BASE_CHAIN && info->target == EBT_RETURN) {
		ebt_print_error("--macencap-target RETURN not allowed on base chain");
	} else {
		CLEAR_BASE_CHAIN_BIT;
		if (strcmp(name, "nat") || hookmask & ~(1 << NF_BR_PRE_ROUTING))
			ebt_print_error("macencap only allowed in PREROUTING");
	}
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	struct ebt_macencap_info *info =
		(struct ebt_macencap_info *)target->data;

	printf(" --encap-smac ");
	ebt_print_mac(info->header.h_source);
	printf(" --encap-dmac ");
	ebt_print_mac(info->header.h_dest);
	printf(" --encap-proto 0x%04x ", ntohs(info->header.h_proto));
	if (info->target != DEFAULT_TARGET)
		printf(" --encap-target %s ", TARGET_NAME(info->target));
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	struct ebt_macencap_info *info1 =
	   (struct ebt_macencap_info *)t1->data;
	struct ebt_macencap_info *info2 =
	   (struct ebt_macencap_info *)t2->data;

	return memcmp(info1, info2, sizeof(struct ebt_macencap_info)) == 0;
}

static struct ebt_u_target macencap_target =
{
	.name			= "macencap",
	.size			= sizeof(struct ebt_macencap_info),
	.help			= print_help,
	.init			= init,
	.parse			= parse,
	.final_check	= final_check,
	.print			= print,
	.compare		= compare,
	.extra_ops		= opts,
};

void _init(void)
{
	ebt_register_target(&macencap_target);
}
