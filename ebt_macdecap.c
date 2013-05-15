/* ebt_macdecap
 *
 * Authors:
 * Huiba Li <lihuiba@gmail.com>
 *
 *  May, 2013
 */

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_macdecap.h>

static unsigned int
ebt_macdecap_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	const struct ebt_macdecap_info *info;

	if (!pskb_pull(skb, ETH_HLEN)) {
		/* unable to extract a mac header */
		return EBT_DROP;
	}
	skb_reset_mac_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_network_header(skb);
	info = par->targinfo;
	return info->target;
}

static bool 
ebt_macdecap_tg_check(const struct xt_tgchk_param *par)
{
	return true;
}

static struct xt_target ebt_macdecap_tg_reg __read_mostly = {
	.name		= "macdecap",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "nat",
	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_PRE_ROUTING),
	.target		= ebt_macdecap_tg,
	.checkentry	= ebt_macdecap_tg_check,
	.targetsize	= sizeof(struct ebt_macdecap_info),
	.me			= THIS_MODULE,
};

static int __init ebt_macdecap_init(void)
{
	return xt_register_target(&ebt_macdecap_tg_reg);
}

static void __exit ebt_macdecap_fini(void)
{
	xt_unregister_target(&ebt_macdecap_tg_reg);
}

module_init(ebt_macdecap_init);
module_exit(ebt_macdecap_fini);
MODULE_DESCRIPTION("Ebtables: MAC decapsulation target");
MODULE_LICENSE("GPL");
