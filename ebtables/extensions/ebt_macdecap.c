/* ebt_macdecap
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
#include <linux/netfilter_bridge/ebt_macdecap.h>

#define DECAP_TARGET '1'
static struct option opts[] =
{
	{ "decap-target" ,  required_argument, 0, DECAP_TARGET },
	{ 0 }
};

static void print_help()
{
	printf(
	"macdecap (MAC decapsulation) target options:\n"
	" --decap-target           : the target of macdecap (default: CONTINUE)\n"
	"\n");
}

#define DEFAULT_TARGET EBT_CONTINUE

static void init(struct ebt_entry_target *target)
{
	struct ebt_macdecap_info *info =
	   (struct ebt_macdecap_info *)target->data;

	info->target = EBT_CONTINUE;
}

#define OPT_TARGET     0x01
static int parse(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	struct ebt_macdecap_info *info =
	   (struct ebt_macdecap_info *)(*target)->data;

	switch (c) {
	case DECAP_TARGET:
		ebt_check_option2(flags, OPT_TARGET);
		if (FILL_TARGET(optarg, info->target))
			ebt_print_error2("Illegal --decap--target target");
		break;

	default:
		printf("parse: unknow char '%c'\n", c);
		return 0;
	}
	return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name,
   unsigned int hookmask, unsigned int time)
{
	struct ebt_macdecap_info *info =
		(struct ebt_macdecap_info *)target->data;

	if (BASE_CHAIN && info->target == EBT_RETURN) {
		ebt_print_error("--macdecap-target RETURN not allowed on base chain");
	} else {
		CLEAR_BASE_CHAIN_BIT;
		if (strcmp(name, "nat") || hookmask & ~(1 << NF_BR_PRE_ROUTING))
			ebt_print_error("macdecap only allowed in PREROUTING");
	}
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	struct ebt_macdecap_info *info =
		(struct ebt_macdecap_info *)target->data;

	if (info->target != DEFAULT_TARGET)
		printf(" --decap-target %s ", TARGET_NAME(info->target));
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	struct ebt_macdecap_info *info1 =
	   (struct ebt_macdecap_info *)t1->data;
	struct ebt_macdecap_info *info2 =
	   (struct ebt_macdecap_info *)t2->data;

	return info1->target == info2->target;
}

static struct ebt_u_target macdecap_target =
{
	.name			= "macdecap",
	.size			= sizeof(struct ebt_macdecap_info),
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
	ebt_register_target(&macdecap_target);
}
