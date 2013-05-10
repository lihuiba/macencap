/* ebt_dumpskb
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

static struct option opts[] =
{
	{ 0 }
};

static void print_help()
{
	printf(
	"dumpskb target options:\n"
	"\n");
}

static void init(struct ebt_entry_target *target)
{
}

static int parse(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name,
   unsigned int hookmask, unsigned int time)
{
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	return 0==0;
}

static struct ebt_u_target dumpskb_target =
{
	.name			= "dumpskb",
	.size			= 0,
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
	ebt_register_target(&dumpskb_target);
}
