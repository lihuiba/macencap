/* ebt_dumpskb
 *
 * Authors:
 * Huiba Li <lihuiba@gmail.com>
 *
 *  May, 2013
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>

static unsigned int
ebt_dumpskb_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	printk("skb: head=%p, end=%d, data=%d, tail=%d, mac_header=%d, network_header=%d, transport_header=%d\n", 
		skb->head, skb->end, skb->data-skb->head, skb->tail, skb->mac_header, skb->network_header, skb->transport_header);
	return EBT_CONTINUE;
}

static bool 
ebt_dumpskb_tg_check(const struct xt_tgchk_param *par)
{
	return true;
}

static struct xt_target ebt_dumpskb_tg_reg __read_mostly = {
	.name		= "dumpskb",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "nat",
	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_PRE_ROUTING),
	.target		= ebt_dumpskb_tg,
	.checkentry	= ebt_dumpskb_tg_check,
	.targetsize	= 0,
	.me			= THIS_MODULE,
};

static int __init ebt_dumpskb_init(void)
{
	int err;
	err = xt_register_target(&ebt_dumpskb_tg_reg);
	return err;
}

static void __exit ebt_dumpskb_fini(void)
{
	xt_unregister_target(&ebt_dumpskb_tg_reg);
}

module_init(ebt_dumpskb_init);
module_exit(ebt_dumpskb_fini);
MODULE_DESCRIPTION("Ebtables: dumpskb target");
MODULE_LICENSE("GPL");

