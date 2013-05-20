
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/configfs.h>
#include <linux/etherdevice.h>



static inline __u32 octets2ip4(__u32 octets[])
{
	return (octets[0]<<24) | (octets[1]<<16) | (octets[2]<<8) | octets[3];
}

static inline void octets2mac(__u32 octets[], char mac[])
{
	mac[0] = octets[0];
	mac[1] = octets[1];
	mac[2] = octets[2];
	mac[3] = octets[3];
	mac[4] = octets[4];
	mac[5] = octets[5];
}

static inline bool alllessthan255(__u32 octets[], int n)
{
	return n==0 || (octets[0]<=255 && alllessthan255(octets+1, n-1));
}

// parse a mac address into [*mac], returning chars consumed, 0 indicating an end or an error
static inline int macscanf(const char* buf, char* mac)
{
	int count, n;
	__u32 octets[ETH_ALEN];
	char temp[ETH_ALEN];

	if (buf==NULL)
	{
		memset(mac, 0, ETH_ALEN);
		return 0;
	}

	n=0;
	count = sscanf(buf, "%2x:%2x:%2x:%2x:%2x:%2x%n",
		&octets[0], &octets[1], &octets[2], &octets[3], &octets[4], &octets[5], &n);
	if (count<ETH_ALEN || !alllessthan255(octets, ETH_ALEN))
		return 0;

	octets2mac(octets, temp);
	if (!is_valid_ether_addr(temp))
		return 0;
	memcpy(mac, temp, ETH_ALEN);
	return n;
}

// parse a ip address into [*ip], returning chars consumed, 0 indicating an end or an error
static inline __u32 ipscanf(const char* buf, __u32* ip)
{
	int count, n;
	__u32 octets[4];

	if (buf==NULL)
	{
		*ip=0;
		return 0;
	}

	n=0;
	count = sscanf(buf, "%3u.%3u.%3u.%3u%n", 
		&octets[3], &octets[2], &octets[1], &octets[0], &n);
	if (count<4 || !alllessthan255(octets, 4))
		return 0;
	
	*ip = octets2ip4(octets);
	return n;
}

#define FOREACH_LINE_PARSE(buf, i, max, parser, out)	\
{														\
	int bytes;											\
	const char* p;										\
	for (i=0,p=buf; i<max && *p!=0; ++i)				\
	{													\
		bytes = parser(p, out);							\
		if (bytes==0) break;							\
		p += bytes;										\
		while (*p!=0 && *p!='\n') ++p;					\
		while (*p!=0 && *p=='\n') ++p;					\
	}													\
	if (i>0 && i<max)									\
		parser(NULL, out);								\
}														\


/* --------------------------- Virtual Machine (vm) ------------------------------------- */
#define VM_MAX_IP 4
#define VM_MAX_NIC 4
struct vm {
	struct config_item item;
	__be32 ip[VM_MAX_IP];
	char mac[VM_MAX_NIC][6];
	char tap[VM_MAX_NIC][32];
	__u32 tanent;
};

/*
static struct config_group *group_pm_make_group(struct config_group *group, const char *name)
{
	struct simple_children *simple_children;

	simple_children = kzalloc(sizeof(struct simple_children),
				  GFP_KERNEL);
	if (!simple_children)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&simple_children->group, name,
				    &simple_children_type);

	return &simple_children->group;
	return ERR_PTR(-ENOMEM);
}
*/

static ssize_t item_vm_description_show(struct vm* vm, char* buf)
{
	return sprintf(buf,
"[virtual machine item]\n"
"This item represents the virtual machine layer of the datacenter hierarchy.\n"
"This item includes attributes [ip], [mac], [tanent] of the VM.\n"
"When storing to [ip] or [mac], multiple values are acceptable, with each on a single line.\n"
"Whereas [tanent] will accept a single positive integer number."
"\n"
);
}

static ssize_t item_vm_ip_show(struct vm* vm, char* buf)
{
	ssize_t size=0, i;
	for (i=0; i<VM_MAX_IP; ++i)
	{
		if (!vm->ip[i]) break;
		size += snprintf(buf+size, PAGE_SIZE-size, "%pI4\n", &vm->ip[i]);
	}
	return size;
}

static ssize_t item_vm_ip_store(struct vm* vm, const char* buf, size_t size)
{
	int i;
	FOREACH_LINE_PARSE(buf, i, VM_MAX_IP, ipscanf, &vm->ip[i]);
	return (i>0) ? size : -EINVAL;
}

static ssize_t item_vm_mac_show(struct vm* vm, char* buf)
{
	ssize_t size=0, i;
	for (i=0; i<VM_MAX_NIC; ++i)
	{
		if (!is_valid_ether_addr(vm->mac[i])) break;
		size += snprintf(buf+size, PAGE_SIZE-size, "%pM\n", vm->mac[i]);
	}
	return size;
}

static ssize_t item_vm_mac_store(struct vm* vm, const char* buf, size_t size)
{
	int i;
	FOREACH_LINE_PARSE(buf, i, VM_MAX_NIC, macscanf, vm->mac[i]);
	return (i>0) ? size : -EINVAL;
}

static ssize_t item_vm_tanent_show(struct vm* vm, char* buf)
{
	return (ssize_t)snprintf(buf, PAGE_SIZE, "%u\n", vm->tanent);
}

static ssize_t item_vm_tanent_store(struct vm* vm, const char* buf, size_t size)
{
	long temp;
	char* endp;
	temp = simple_strtol(buf, &endp, 10);
	if (!endp || (*endp && *endp!='\n'))
		return -EINVAL;
	vm->tanent = (__u32)temp;
	return size;
}

static inline struct vm* to_vm(struct config_item* item)
{
	return item ? container_of(item, struct vm, item) : NULL;
}

struct vm_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct vm*, char*);
	ssize_t (*store)(struct vm*, const char*, size_t);
};

static struct vm_attribute item_vm_attr_description = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "description",
		.ca_mode = S_IRUGO,
	},
	.show = item_vm_description_show,
};

static struct vm_attribute item_vm_attr_ip = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "ip",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = item_vm_ip_show,
	.store = item_vm_ip_store,
};

static struct vm_attribute item_vm_attr_mac = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "mac",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = item_vm_mac_show,
	.store = item_vm_mac_store,
};

static struct vm_attribute item_vm_attr_tanent = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "tanent",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = item_vm_tanent_show,
	.store = item_vm_tanent_store,
};

static ssize_t item_vm_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	struct vm* vm = to_vm(item);
	struct vm_attribute* vm_attr = container_of(attr, struct vm_attribute, attr);
	return vm_attr->show ? vm_attr->show(vm, page) : 0;
}

static ssize_t item_vm_attr_store(struct config_item *item,
					struct configfs_attribute *attr,
					const char *page, size_t count)
{
	struct vm* vm = to_vm(item);
	struct vm_attribute* vm_attr = container_of(attr, struct vm_attribute, attr);
	return vm_attr->store ? vm_attr->store(vm, page, count) : -EINVAL;
}

static struct configfs_attribute *item_vm_attrs[] = {
	&item_vm_attr_description.attr,
	&item_vm_attr_ip.attr,
	&item_vm_attr_mac.attr,
	&item_vm_attr_tanent.attr,
	NULL,
};

static struct configfs_item_operations item_vm_item_ops = {
	.show_attribute	= item_vm_attr_show,
	.store_attribute = item_vm_attr_store,
};
/*
static struct configfs_group_operations group_pm_group_ops = {
	.make_group	= group_pm_make_group,
};
*/
static struct config_item_type item_vm_type = {
	.ct_item_ops	= &item_vm_item_ops,
//	.ct_group_ops	= &group_pm_group_ops,
	.ct_attrs		= item_vm_attrs,
	.ct_owner		= THIS_MODULE,
};



/* --------------------------- Physical Machine (pm) ------------------------------------- */
#define PM_MAX_IP 40
#define PM_MAX_MAC 4
struct pm {
	struct config_group group;
	__be32 ip[PM_MAX_IP];
	char mac[PM_MAX_MAC][6];
};

static struct config_item *group_pm_make_item(struct config_group *group, const char *name)
{
	struct vm* vm;

	vm = kzalloc(sizeof(struct vm), GFP_KERNEL);
	if (!vm)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&vm->item, name, &item_vm_type);

	return &vm->item;
}

static ssize_t group_pm_description_show(struct pm* pm, char* buf)
{
	return sprintf(buf,
"[physical machine group]\n"
"\n"
"This group represents the physical machine (server) layer of the datacenter hierarchy.\n"
"This group includes attributes [ip], [mac] of the machine.\n"
"This group allows the creation of the virtual machines by mkdir.\n"
"\n"
"When storing to [ip] or [mac], multiple values are acceptable, with each on a single line.\n"
"\n"
);
}

static ssize_t group_pm_ip_show(struct pm* pm, char* buf)
{
	ssize_t size=0, i;
	for (i=0; i<PM_MAX_IP; ++i)
	{
		if (!pm->ip[i]) break;
		size += snprintf(buf+size, PAGE_SIZE-size, "%pI4\n", &pm->ip[i]);
	}
	return size;
}

static ssize_t group_pm_ip_store(struct pm* pm, const char* buf, size_t size)
{
	int i;
	FOREACH_LINE_PARSE(buf, i, PM_MAX_IP, ipscanf, &pm->ip[i]);
	return (i>0) ? size : -EINVAL;
}

static ssize_t group_pm_mac_show(struct pm* pm, char* buf)
{
	ssize_t size=0, i;
	for (i=0; i<PM_MAX_MAC; ++i)
	{
		if (!is_valid_ether_addr(pm->mac[i])) break;
		size += snprintf(buf+size, PAGE_SIZE-size, "%pM\n", pm->mac[i]);
	}
	return size;
}


static ssize_t group_pm_mac_store(struct pm* pm, const char* buf, size_t size)
{
	int i;
	FOREACH_LINE_PARSE(buf, i, PM_MAX_MAC, macscanf, pm->mac[i]);
	return (i>0) ? size : -EINVAL;
}

static inline struct pm* to_pm(struct config_item* item)
{
	return item ? container_of(to_config_group(item), struct pm, group) : NULL;
}

struct pm_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct pm*, char*);
	ssize_t (*store)(struct pm*, const char*, size_t);
};

static struct pm_attribute group_pm_attr_description = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "description",
		.ca_mode = S_IRUGO,
	},
	.show = group_pm_description_show,
};

static struct pm_attribute group_pm_attr_ip = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "ip",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = group_pm_ip_show,
	.store = group_pm_ip_store,
};

static struct pm_attribute group_pm_attr_mac = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "mac",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = group_pm_mac_show,
	.store = group_pm_mac_store,
};

static ssize_t group_pm_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	struct pm* pm = to_pm(item);
	struct pm_attribute* pm_attr = container_of(attr, struct pm_attribute, attr);
	return pm_attr->show ? pm_attr->show(pm, page) : 0;
}

static ssize_t group_pm_attr_store(struct config_item *item,
					struct configfs_attribute *attr,
					const char *page, size_t count)
{
	struct pm* pm = to_pm(item);
	struct pm_attribute* pm_attr = container_of(attr, struct pm_attribute, attr);
	return pm_attr->store ? pm_attr->store(pm, page, count) : -EINVAL;
}

static struct configfs_attribute *group_pm_attrs[] = {
	&group_pm_attr_description.attr,
	&group_pm_attr_ip.attr,
	&group_pm_attr_mac.attr,
	NULL,
};

static struct configfs_item_operations group_pm_item_ops = {
	.show_attribute	= group_pm_attr_show,
	.store_attribute = group_pm_attr_store,
};

static struct configfs_group_operations group_pm_group_ops = {
	.make_item	= group_pm_make_item,
};

static struct config_item_type group_pm_type = {
	.ct_item_ops	= &group_pm_item_ops,
	.ct_group_ops	= &group_pm_group_ops,
	.ct_attrs		= group_pm_attrs,
	.ct_owner		= THIS_MODULE,
};




/* --------------------------- network ------------------------------------- */
#define MAX_ROUTER 8
#define MAX_NETWORK 20
struct msroute_info_type {
	char router_mac[6];
	__s32 networks[MAX_NETWORK];
};

struct network {
	struct config_group group;
	__s32 number;
	__be32 network;
	__be32 network_mask;
};

static struct config_group *group_network_make_group(struct config_group *group, const char *name)
{
	struct pm* pm;
	pm = kzalloc(sizeof(struct pm), GFP_KERNEL);
	if (!pm)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&pm->group, name,
				    &group_pm_type);

	return &pm->group;
}

static ssize_t group_network_description_show(struct network* network, char* buf)
{
	return sprintf(buf,
"[network group]\n"
"\n"
"This group represents the L2 network layer of the datacenter hierarchy.\n"
"This group includes attributes [number], [iprange] of the network.\n"
"This group allows the creation of the physical machines by mkdir.\n"
"\n"
"When storing to [iprange], either format '*.*.*.*/*' or '*.*.*.*\\n*.*.*.*' is acceptable.\n"
"\n"
);
}

static ssize_t group_network_number_show(struct network* network, char* buf)
{
	return (ssize_t)snprintf(buf, PAGE_SIZE, "%d\n", network->number);
}

static ssize_t group_network_number_store(struct network* network, const char* buf, size_t size)
{
	long temp;
	char* endp;
	temp = simple_strtol(buf, &endp, 10);
	if (!endp || (*endp && *endp!='\n'))
		return -EINVAL;
	network->number = (__s32)temp;
	return size;
}

static ssize_t group_network_iprange_show(struct network* network, char* buf)
{
	return (ssize_t)snprintf(buf, PAGE_SIZE, "%pI4\n%pI4\n", 
		&network->network, &network->network_mask);
}

static ssize_t group_network_iprange_store(struct network* network, const char* buf, size_t size)
{
	int ret;
	__u32 octets[8], mask, ipv4_addr, t;

	ret = sscanf(buf, "%3u.%3u.%3u.%3u/%u", &octets[0], &octets[1], &octets[2], &octets[3], &mask);
	if (ret==5)
	{
		if (mask>32 || !alllessthan255(octets, 4))
			return -EINVAL;
		mask = ~((1ul<<(32-mask))-1);
		ipv4_addr = octets2ip4(octets);
	}
	else
	{
		ret = sscanf(buf, "%3u.%3u.%3u.%3u\n%3u.%3u.%3u.%3u", 
			&octets[0], &octets[1], &octets[2], &octets[3], 
			&octets[4], &octets[5], &octets[6], &octets[7]);
		if (ret!=8 || !alllessthan255(octets, 8))
			return -EINVAL;
		mask = octets2ip4(octets+4);
		t = (~mask) + 1;
		if ( (t&mask) != t )
		{
			printk("t=%x, mask=%x", t, mask);
			return -EINVAL;
		}
		ipv4_addr = octets2ip4(octets);
	}

	network->network = htonl(ipv4_addr);
	network->network_mask = htonl(mask);
	return size;
}
/*
static ssize_t group_network_routers_show(struct network* network, char* buf)
{

}

static ssize_t group_network_routers_store(struct network* network, const char* buf, size_t size)
{

}
*/
static inline struct network* to_network(struct config_item* item)
{
	return item ? container_of(to_config_group(item), struct network, group) : NULL;
}

struct network_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct network*, char*);
	ssize_t (*store)(struct network*, const char*, size_t);
};

static struct network_attribute group_network_attr_description = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "description",
		.ca_mode = S_IRUGO,
	},
	.show = group_network_description_show,
};

static struct network_attribute group_network_attr_number = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "number",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = group_network_number_show,
	.store = group_network_number_store,
};

static struct network_attribute group_network_attr_iprange = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "iprange",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = group_network_iprange_show,
	.store = group_network_iprange_store,
};

static ssize_t group_network_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	struct network* network = to_network(item);
	struct network_attribute* network_attr = container_of(attr, struct network_attribute, attr);
	return network_attr->show ? network_attr->show(network, page) : 0;
}

static ssize_t group_network_attr_store(struct config_item *item,
					struct configfs_attribute *attr,
					const char *page, size_t count)
{
	struct network* network = to_network(item);
	struct network_attribute* network_attr = container_of(attr, struct network_attribute, attr);
	return network_attr->store ? network_attr->store(network, page, count) : -EINVAL;
}

static struct configfs_attribute *group_network_attrs[] = {
	&group_network_attr_description.attr,
	&group_network_attr_number.attr,
	&group_network_attr_iprange.attr,
	NULL,
};

static struct configfs_item_operations group_network_item_ops = {
	.show_attribute	= group_network_attr_show,
	.store_attribute = group_network_attr_store,
};

static struct configfs_group_operations group_network_group_ops = {
	.make_group	= group_network_make_group,
};

static struct config_item_type group_network_type = {
	.ct_item_ops	= &group_network_item_ops,
	.ct_group_ops	= &group_network_group_ops,
	.ct_attrs		= group_network_attrs,
	.ct_owner		= THIS_MODULE,
};



/* --------------------------- datacenter ------------------------------------- */

static struct config_group* group_datacenter_make_group(struct config_group *group, const char *name)
{
	struct network* network;
	network = kzalloc(sizeof(struct network), GFP_KERNEL);
	if (!network)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&network->group, name,
				    &group_network_type);

	return &network->group;
}

static ssize_t group_datacenter_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	return sprintf(page,
"[datacenter group]\n"
"\n"
"This group represents the top layer of the datacenter hierarchy.\n"
"This group allows the creation of the L2 netowrk(s) by mkdir.\n"
);
}

static struct configfs_attribute group_datacenter_attr_description = {
	.ca_owner = THIS_MODULE,
	.ca_name = "description",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *group_datacenter_attrs[] = {
	&group_datacenter_attr_description,
	NULL,
};

static struct configfs_item_operations group_datacenter_item_ops = {
	.show_attribute	= group_datacenter_attr_show,
};

static struct configfs_group_operations group_datacenter_group_ops = {
	.make_group	= group_datacenter_make_group,
};

static struct config_item_type group_datacenter_type = {
	.ct_item_ops	= &group_datacenter_item_ops,
	.ct_group_ops	= &group_datacenter_group_ops,
	.ct_attrs		= group_datacenter_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct configfs_subsystem group_datacenter_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "datacenter",
			.ci_type = &group_datacenter_type,
		},
	},
};

/* --------------------------- router ------------------------------------- */

struct nic {
	char mac[6];
	__u16 network;
};

#define MAX_NICS 48
struct router
{
	struct config_item item;
	struct nic nics[MAX_NICS];
};

static inline struct router* to_router(struct config_item* p)
{
	return p ? container_of(p, struct router, item) : NULL;
}

static void item_router_release(struct config_item *item)
{
	kfree(to_router(item));
}

static ssize_t item_router_description_show(struct router* router, char* page)
{
	return sprintf(page,
"[router item]\n"
"This group describes infomation for a single ms-router.\n"
"Each line in [nic] has the pattern of 'number  mac', respectively "
"presenting network number and associated NIC's mac address on the "
"router. One network maybe reachable via multiple NICs.\n"
"\n"
);
}

static ssize_t item_router_nic_show(struct router* router, char* buf)
{
	ssize_t size=0, i;
	for (i=0; i<MAX_NICS; ++i)
	{
		if (!is_valid_ether_addr(router->nics[i].mac)) break;
		size += snprintf(buf+size, PAGE_SIZE-size, "%u\t%pM\n", 
			router->nics[i].network, &router->nics[i].mac);
	}
	return size;
}

static inline int nicscanf(const char* buf, struct nic* nic)
{
	int network, bytes1, bytes2, count;

	if (buf==NULL)
	{
		memset(nic, 0, sizeof(struct nic));
		return 0;
	}

	bytes1=0;
	count = sscanf(buf, "%d %n", &network, &bytes1);
	if (count<1)
	{
		printk("nicscanf: sscanf() failed, bytes1=%d\n", bytes1);
		return -EINVAL;
	}
	
	bytes2 = macscanf(buf+bytes1, nic->mac);
	if (bytes2==0)
	{
		printk("nicscanf: macscanf failed, str='%s', bytes1=%d\n", buf, bytes2);
		return -EINVAL;
	}

	nic->network = (__u16)network;
	return bytes1+bytes2;
}

static ssize_t item_router_nic_store(struct router* router, const char* buf, size_t size)
{
	int i;
	FOREACH_LINE_PARSE(buf, i, MAX_NICS, nicscanf, &router->nics[i]);
	printk("item_router_nic_store i=%d\n", i);
	return (i>0) ? size : -EINVAL;
}

struct router_attribute
{
	struct configfs_attribute attr;
	ssize_t (*show)(struct router*, char*);
	ssize_t (*store)(struct router*, const char*, size_t);
};

static struct router_attribute item_router_attr_description = {
	.attr={
		.ca_owner = THIS_MODULE,
		.ca_name = "description",
		.ca_mode = S_IRUGO,
	},
	.show = item_router_description_show,
	//.store = item_router_description_store,
};

static struct router_attribute item_router_attr_nic = {
	.attr={
		.ca_owner = THIS_MODULE,
		.ca_name = "nic",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = item_router_nic_show,
	.store = item_router_nic_store,
};

static struct configfs_attribute *item_router_attrs[] = {
	&item_router_attr_description.attr,
	&item_router_attr_nic.attr,
	NULL,
};

static ssize_t item_router_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	struct router* router = to_router(item);
	struct router_attribute* router_attr = container_of(attr, struct router_attribute, attr);
	return router_attr->show ? router_attr->show(router, page) : 0;
}

static ssize_t item_router_attr_store(struct config_item *item,
					struct configfs_attribute *attr,
					const char *page, size_t count)
{
	struct router* router = to_router(item);
	struct router_attribute* router_attr = container_of(attr, struct router_attribute, attr);
	return router_attr->store ? router_attr->store(router, page, count) : -EINVAL;
}

static struct configfs_item_operations item_router_item_ops = {
	.release = &item_router_release,
	.show_attribute	= &item_router_attr_show,
	.store_attribute = &item_router_attr_store,
};

static struct config_item_type item_router_type = {
	.ct_item_ops	= &item_router_item_ops,
	.ct_attrs		= item_router_attrs,
	.ct_owner		= THIS_MODULE,
};

/* --------------------------- routers ------------------------------------- */

static struct config_item* group_routers_make_item(struct config_group *group, const char *name)
{
	struct router* router;
	router = kzalloc(sizeof(struct router), GFP_KERNEL);
	if (!router)
		return ERR_PTR(-ENOMEM);

	//printk("group_routers_make_item: router=%p\n", router);

	config_item_init_type_name(&router->item, name,
				    &item_router_type);

	return &router->item;
}

static ssize_t group_routers_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	return sprintf(page,
"[router group]\n"
"This group includes msrouter infomation in each sub-directory.\n"
"To add a new router, simply use mkdir and fill in infomation in the created directory.\n"
"\n"
);
}

static struct configfs_attribute group_routers_attr_description = {
	.ca_owner = THIS_MODULE,
	.ca_name = "description",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *group_routers_attrs[] = {
	&group_routers_attr_description,
	NULL,
};

static struct configfs_item_operations group_routers_item_ops = {
	.show_attribute	= &group_routers_attr_show,
};

static struct configfs_group_operations group_routers_group_ops = {
	.make_item	= &group_routers_make_item,
};

static struct config_item_type group_routers_type = {
	.ct_item_ops	= &group_routers_item_ops,
	.ct_group_ops	= &group_routers_group_ops,
	.ct_attrs		= group_routers_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct configfs_subsystem group_routers_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "routers",
			.ci_type = &group_routers_type,
		},
	},
};

/* --------------------------- tanent ------------------------------------- */
struct tanent
{
	struct config_item item;
	__u32 id;
	char name[32];
};

static inline struct tanent* to_tanent(struct config_item* p)
{
	return p ? container_of(p, struct tanent, item) : NULL;
}

static void item_tanent_release(struct config_item *item)
{
	kfree(to_tanent(item));
}

static ssize_t item_tanent_description_show(struct tanent* tanent, char* page)
{
	return sprintf(page,
"[tanent item]\n"
"This group describes infomation for a single tanent.\n"
"\n"
);
}

static ssize_t item_tanent_id_show(struct tanent* tanent, char* buf)
{
	return (ssize_t)snprintf(buf, PAGE_SIZE, "%u\n", tanent->id);
}

static ssize_t item_tanent_id_store(struct tanent* tanent, const char* buf, size_t size)
{
	long temp;
	char* endp;
	temp = simple_strtol(buf, &endp, 10);
	if (!endp || (*endp && *endp!='\n'))
		return -EINVAL;
	tanent->id = (__u32)temp;
	return size;
}

static ssize_t item_tanent_name_show(struct tanent* tanent, char* buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", tanent->name);
}

static ssize_t item_tanent_name_store(struct tanent* tanent, const char* buf, size_t size)
{
	int ret;
	ret = sscanf(buf, "%32s", tanent->name);
	//printk("item_tanent_name_store.sscanf: ret=%d, len=%d, tanent->name='%s'\n", ret, len, tanent->name);
	return (ret==1) ? size : 0;
}

struct tanent_attribute
{
	struct configfs_attribute attr;
	ssize_t (*show)(struct tanent*, char*);
	ssize_t (*store)(struct tanent*, const char*, size_t);
};

static struct tanent_attribute item_tanent_attr_description = {
	.attr={
		.ca_owner = THIS_MODULE,
		.ca_name = "description",
		.ca_mode = S_IRUGO,
	},
	.show = item_tanent_description_show,
	//.store = item_router_description_store,
};

static struct tanent_attribute item_tanent_attr_id = {
	.attr={
		.ca_owner = THIS_MODULE,
		.ca_name = "id",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = item_tanent_id_show,
	.store = item_tanent_id_store,
};

static struct tanent_attribute item_tanent_attr_name = {
	.attr={
		.ca_owner = THIS_MODULE,
		.ca_name = "name",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = item_tanent_name_show,
	.store = item_tanent_name_store,
};

static struct configfs_attribute *item_tanent_attrs[] = {
	&item_tanent_attr_description.attr,
	&item_tanent_attr_name.attr,
	&item_tanent_attr_id.attr,
	NULL,
};

static ssize_t item_tanent_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	struct tanent* tanent = to_tanent(item);
	struct tanent_attribute* tanent_attr = container_of(attr, struct tanent_attribute, attr);
	return tanent_attr->show ? tanent_attr->show(tanent, page) : 0;
}

static ssize_t item_tanent_attr_store(struct config_item *item,
					struct configfs_attribute *attr,
					const char *page, size_t count)
{
	struct tanent* tanent = to_tanent(item);
	struct tanent_attribute* tanent_attr = container_of(attr, struct tanent_attribute, attr);
	return tanent_attr->store ? tanent_attr->store(tanent, page, count) : -EINVAL;
}

static struct configfs_item_operations item_tanent_item_ops = {
	.release = &item_tanent_release,
	.show_attribute	= &item_tanent_attr_show,
	.store_attribute = &item_tanent_attr_store,
};

static struct config_item_type item_tanent_type = {
	.ct_item_ops	= &item_tanent_item_ops,
	.ct_attrs		= item_tanent_attrs,
	.ct_owner		= THIS_MODULE,
};

/* --------------------------- tanents ------------------------------------- */

static struct config_item* group_tanents_make_item(struct config_group *group, const char *name)
{
	struct tanent* tanent;
	tanent = kzalloc(sizeof(struct tanent), GFP_KERNEL);
	if (!tanent)
		return ERR_PTR(-ENOMEM);

	//printk("group_tanents_make_item: tanent=%p\n", tanent);

	config_item_init_type_name(&tanent->item, name, &item_tanent_type);

	return &tanent->item;
}

static ssize_t group_tanents_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	return sprintf(page,
"[tanents group]\n"
"This group includes tanents infomation in each sub-directory.\n"
"To add a new tanent, simply use mkdir and fill in infomation in the created directory.\n"
"\n"
);
}

static struct configfs_attribute group_tanents_attr_description = {
	.ca_owner = THIS_MODULE,
	.ca_name = "description",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *group_tanents_attrs[] = {
	&group_tanents_attr_description,
	NULL,
};

static struct configfs_item_operations group_tanents_item_ops = {
	.show_attribute	= &group_tanents_attr_show,
};

static struct configfs_group_operations group_tanents_group_ops = {
	.make_item	= &group_tanents_make_item,
};

static struct config_item_type group_tanents_type = {
	.ct_item_ops	= &group_tanents_item_ops,
	.ct_group_ops	= &group_tanents_group_ops,
	.ct_attrs		= group_tanents_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct configfs_subsystem group_tanents_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "tanents",
			.ci_type = &group_tanents_type,
		},
	},
};

/* ----------------------------------------------------------------- */

static struct configfs_subsystem *all_subsys[] = {
	&group_datacenter_subsys,
	&group_routers_subsys,
	&group_tanents_subsys,
	NULL,
};

static int __init macencap_config_init(void)
{
	int i, ret;
	struct configfs_subsystem *subsys;

	for (i = 0; all_subsys[i]; i++) {
		subsys = all_subsys[i];

		config_group_init(&subsys->su_group);
		mutex_init(&subsys->su_mutex);
		ret = configfs_register_subsystem(subsys);
		if (ret) {
			printk(KERN_ERR "Error %d while registering subsystem %s\n",
			       ret, subsys->su_group.cg_item.ci_namebuf);
			goto out_unregister;
		}
	}

	return 0;

out_unregister:
	for (; i >= 0; i--) {
		configfs_unregister_subsystem(all_subsys[i]);
	}

	return ret;
}

static void __exit macencap_config_exit(void)
{
	int i;

	for (i = 0; all_subsys[i]; i++) {
		configfs_unregister_subsystem(all_subsys[i]);
	}
}

module_init(macencap_config_init);
module_exit(macencap_config_exit);
MODULE_LICENSE("GPL");

