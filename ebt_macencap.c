/* ebt_macencap
 *
 * Authors:
 * Huiba Li <lihuiba@gmail.com>
 *
 *  May, 2013
 */

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_macencap.h>

static unsigned int
ebt_macencap_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	struct ethhdr* newheader;
	const struct ebt_macencap_info *info;

	if (!skb_make_writable(skb, 0))
		return EBT_DROP;

	if (skb_headroom(skb) < ETH_HLEN*2) {
		/* no enough space for a new mac header */
		/* TODO: re-allocate a new skb */
		return EBT_DROP;
	}

	//skb->encapsulation
	//skb_set_inner_transport_header
	//skb_set_inner_network_header

	unsigned int delta = skb->data - skb_mac_header(skb) + ETH_HLEN;
	newheader = (struct ethhdr*)skb_push(skb, delta);
	memcpy(newheader, &info->header, ETH_HLEN);
	//skb->mac_header -= ETH_HELN;
	skb_reset_mac_header(skb);	// mac_header==data
	skb->protocol = eth_type_trans(skb, skb->dev);  // implicitly reset mac header and pull a ETH_HLEN length
	skb_reset_network_header(skb);
	skb_reset_mac_len(skb);
	
	info = par->targinfo;
	return info->target;
}

static bool 
ebt_macencap_tg_check(const struct xt_tgchk_param *par)
{
	const struct ebt_macencap_info *info = par->targinfo;
	const struct ethhdr* header = &info->header;
	if (ntohs(header->h_proto) <= 0x0600) {
		/* protocol type is NOT allowed to be less or equal to 0x0600 */
		return false;
	}
	if (!is_valid_ether_addr(header->h_dest))
	{
		/* no destination address */
		return false;
	}

	return true;
}

static struct xt_target ebt_macencap_tg_reg __read_mostly = {
	.name		= "macencap",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "nat",
	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_PRE_ROUTING),
	.target		= ebt_macencap_tg,
	.checkentry	= ebt_macencap_tg_check,
	.targetsize	= sizeof(struct ebt_macencap_info),
	.me			= THIS_MODULE,
};

static int __init ebt_macencap_init(void)
{
	return xt_register_target(&ebt_macencap_tg_reg);
}

static void __exit ebt_macencap_fini(void)
{
	xt_unregister_target(&ebt_macencap_tg_reg);
}

module_init(ebt_macencap_init);
module_exit(ebt_macencap_fini);
MODULE_DESCRIPTION("Ebtables: MAC encapsulation target");
MODULE_LICENSE("GPL");

