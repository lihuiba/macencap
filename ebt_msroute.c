/* ebt_msroute
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
#include <linux/netfilter_bridge/ebt_msroute.h>


struct record {
	char devname[IFNAMSIZ];
	__u16 network;
};

#define MAX_NET_DEVICES 256
#define MAX_NETWORKS 65536
#define INVALID_NETWORK 0xffff
#define INVALID_DEV 0xff

struct record record[MAX_NET_DEVICES];
struct net_device* netdevs[MAX_NET_DEVICES];
__u16 dev2network[MAX_NET_DEVICES];
__u32 network2dev[MAX_NETWORKS];   // 4 bytes each representing a dev index;

static int
netdevs_update(struct net_device* from, struct net_device* to)
{
	int i;
	for (i=0; i<MAX_NET_DEVICES; i++)
		if (netdevs[i]==from)
		{
			netdevs[i] = to;
			return i;
		}
	return -1;
}

static __u16
search_device_for_network(struct net_device* netdev)
{
	int i;
	for (i=0; i<MAX_NET_DEVICES; ++i)
		if (strcmp(netdev->name, record[i].devname)==0)
			return record[i].network;
	return INVALID_NETWORK;
}

static inline void
encode_update(__u32* code, __u8 from, __u8 to)
{
	__u8* p = (__u8*)code;
	if (p[0]==from) p[0]=to;
	else if (p[1]==from) p[1]=to;
	else if (p[2]==from) p[2]=to;
	else if (p[3]==from) p[3]=to;
}

static inline void
encode_add(__u32* code, __u8 dev)
{
	encode_update(code, INVALID_DEV, dev);
}

static inline void
encode_remove(__u32* code, __u8 dev)
{
	encode_update(code, dev, INVALID_DEV);
}

static inline __u8
decode_rotate_get(__u32* code)
{
	if (*code==0xffffffff)
		return INVALID_DEV;

	do {
		*code = (*code >> 8) | (*code << 24);	//rotate shifting 1 byte
	} while ( *(__u8*)code != INVALID_DEV);
	return *(__u8*)code;
}

static void netdev_put(struct net_device* netdev)
{
	__u16 network;
	int dev = netdevs_update(NULL, netdev);
	if (dev==-1)
		return;
	network = search_device_for_network(netdev);
	dev2network[dev] = network;
	encode_add(&network2dev[network], dev);
}

static inline void netdev_remove(struct net_device* netdev)
{
	__u16 network;
	int dev = netdevs_update(netdev, NULL);
	if (dev==-1)
		return;
	network = search_device_for_network(netdev);
	dev2network[dev] = INVALID_NETWORK;
	encode_remove(&network2dev[network], dev);
}

static int netdev_index(struct net_device* netdev)
{
	int i;
	for (i=0; i<MAX_NET_DEVICES; ++i)
		if (netdevs[i]==netdev)
			return i;
	return INVALID_DEV;
}

// stolen from br_forward.c
static int 
br_dev_queue_push_xmit(struct sk_buff *skb)
{
	/* drop mtu oversized packets except gso */
//	if (packet_length(skb) > skb->dev->mtu && !skb_is_gso(skb))
//		kfree_skb(skb);
//	else {
		/* ip_refrag calls ip_fragment, doesn't copy the MAC header. */
//		if (nf_bridge_maybe_copy_header(skb))
//			kfree_skb(skb);
//		else {
			skb_push(skb, ETH_HLEN);

			dev_queue_xmit(skb);
//		}
//	}

	return 0;
}

// stolen from br_forward.c
static int
br_forward_finish(struct sk_buff* skb)
{
	return NF_HOOK(PF_BRIDGE, NF_BR_POST_ROUTING, skb, NULL, skb->dev,
		       br_dev_queue_push_xmit);
}

static unsigned int
ebt_msroute_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	const struct ebt_msroute_info *info;
	struct msrhdr* hdr;
	unsigned char temp[ETH_ALEN];
	__u16 outNW;
	int index;

	info = par->targinfo;
	hdr = (struct msrhdr*)eth_hdr(skb);
	outNW = ntohs(hdr->NW);
	
	// step1: (DST, SRC, MAC3) = (MAC3, DST, SRC)
	memcpy(temp,					hdr->ethhdr.h_dest,		ETH_ALEN);
	memcpy(hdr->ethhdr.h_dest,		hdr->h_mac3,			ETH_ALEN);
	memcpy(hdr->h_mac3,				hdr->ethhdr.h_source,	ETH_ALEN);
	memcpy(hdr->ethhdr.h_source,	temp,					ETH_ALEN);

	// step2: lookup NW of source network
	index = netdev_index(skb->dev);
	hdr->NW = htons(dev2network[index]);

	// step3: lookup the nic of NW and fast forward the packet by outNW,
	if (info->fast_forward)			// forward by hdr->NW
	{
		index = network2dev[outNW];
		if (index!=INVALID_DEV && netdevs[index]!=NULL)
		{
			atomic_inc(&skb->users);
			skb->dev = netdevs[index];	// lookup out nic by outNW
			br_forward_finish(skb);		// jump to POSTROUTING
			return EBT_DROP;			// avoid normal forwarding 
		}
	}
	// or normal forward by hdr->ethhdr.h_dest
	return info->target;
}

static bool 
ebt_msroute_tg_check(const struct xt_tgchk_param *par)
{
	return true;
}

static struct xt_target ebt_msroute_tg_reg __read_mostly = {
	.name		= "msroute",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "nat",
	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_PRE_ROUTING),
	.target		= ebt_msroute_tg,
	.checkentry	= ebt_msroute_tg_check,
	.targetsize	= sizeof(struct ebt_msroute_info),
	.me			= THIS_MODULE,
};

static int net_device_event(struct notifier_block* unused, unsigned long event, void* ptr)
{
	struct net_device* dev = ptr;
	//struct net_bridge_port* p = dev->br_port;
	//struct net_bridge* br;

	// not a port of a bridge
	//if (p==NULL)
	//	return NOTIFY_DONE;

	//br = p->br;

	switch(event)
	{
		case NETDEV_REGISTER:
		netdev_put(dev);
		break;

		case NETDEV_UNREGISTER:
		netdev_remove(dev);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block br_device_notifier = {
	.notifier_call = net_device_event,
};

static int __init ebt_msroute_init(void)
{
	int err;
	memset(netdevs, 0, sizeof(netdevs));
	memset(dev2network, -1, sizeof(dev2network));
	memset(network2dev, -1, sizeof(network2dev));
	err = register_netdevice_notifier(&br_device_notifier);
	if (err)
		goto out;

	err = xt_register_target(&ebt_msroute_tg_reg);
	if (err)
		goto out1;

	return 0;

out1:
	unregister_netdevice_notifier(&br_device_notifier);
out:
	return err;
}

static void __exit ebt_msroute_fini(void)
{
	unregister_netdevice_notifier(&br_device_notifier);
	xt_unregister_target(&ebt_msroute_tg_reg);
}

module_init(ebt_msroute_init);
module_exit(ebt_msroute_fini);
MODULE_DESCRIPTION("Ebtables: MAC Source Routing target");
MODULE_LICENSE("GPL");

