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
#include "macache.h"
#include "ebt_macencap.h"

static unsigned int
ebt_macencap_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	u64 mac64;
	const struct ebt_macencap_info *info;
	const struct ethhdr* old_header = eth_hdr(skb);

	if (!skb_make_writable(skb, 0))
		return EBT_DROP;

	if (skb_headroom(skb) < ETH_HLEN) {
		/* no enough space for a new mac header */
		/* TODO: re-allocate a new skb */
		return EBT_DROP;
	}

	info = par->targinfo;
	skb->mac_header -= ETH_HLEN;
	skb->data -= ETH_HLEN;
	skb->transport_header -= ETH_HLEN;
	skb->network_header -= ETH_HLEN;
	skb->protocol = info->header.h_proto;
	skb->len += ETH_HLEN;

	//memcpy(skb_mac_header(skb), &info->header, ETH_HLEN);
	mac64 = mac2u64(info->header.h_dest);
	if (mac64 == 0)
	{
		char* mac = macache_get(old_header->h_dest);
		if (mac != NULL)
			mac64 = mac2u64(mac);
		else
		{
			mac64 = 0xffffffffffff;		//broadcast address
			skb->pkt_type = PACKET_BROADCAST;
		}
	}
	mac_setu64(eth_hdr(skb)->h_dest, mac64);

	mac64 = mac2u64(info->header.h_source);
//	if (unlikely(mac64 == 0))
//	{
//		mac64 = mac2u64(par->in->br_port->br->dev->dev_addr);
//		mac_setu64((char*)info->header.h_source, mac64);
//	}
	mac_setu64(eth_hdr(skb)->h_source, mac64);

	eth_hdr(skb)->h_proto = info->header.h_proto;

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
//	.table		= "nat",
//	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_PRE_ROUTING),
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

