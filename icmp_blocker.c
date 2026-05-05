#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/icmp.h>
#include<linux/ip.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>

static struct nf_hook_ops icmp_hook;

static unsigned int block_icmp(
	void *priv,
	struct sk_buff *skb,
	const struct nf_hook_state *state
)
{
	struct iphdr *ip_header;
	if(!skb) return NF_ACCEPT;
	ip_header = ip_hdr(skb);
	if(!ip_header) return NF_ACCEPT;
	if(ip_header->protocol == IPPROTO_ICMP){
		printk(KERN_ALERT "icmp packet dropped\n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}
static int __init main(void){
	icmp_hook.hook=block_icmp;
	icmp_hook.pf=PF_INET;
	icmp_hook.hooknum=NF_INET_PRE_ROUTING;
	icmp_hook.priority=NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net,&icmp_hook);
	printk(KERN_INFO "hook working \n");

	return 0;
}

static void __exit exit(void){
	nf_unregister_net_hook(&init_net, &icmp_hook);
	printk(KERN_INFO "unloading from kernel \n");
}

module_init(main);
module_exit(exit);
MODULE_AUTHOR("STARS");
MODULE_LICENSE("GPL");
