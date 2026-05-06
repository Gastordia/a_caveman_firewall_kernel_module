#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/netfilter_ipv6.h>
#include<linux/ip.h>
#include<linux/icmp.h>
#include<linux/ipv6.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<net/net_namespace.h>

#define max_ports 32

static int ipv4_param = 0;
static int ipv6_param = 0;
static int icmp_param = 0;

static int allowed_ports[max_ports] = {0};
static int ports_count = 0 ;

module_param(ipv4_param, int, 0644);
module_param(ipv6_param, int, 0644);
module_param(icmp_param, int, 0644);

static struct nf_hook_ops ipv4_in_hook;
static struct nf_hook_ops ipv6_in_hook;
static struct nf_hook_ops ipv6_out_hook;
module_param_array_named(ports, allowed_ports, int, &ports_count, 0644);

static bool is_port_allowd(unsigned short port){
	int i;
	if (ports_count == 0) return true;
	if (ports_count == 1 && allowed_ports[0]==0) return false ;
	for (i = 0 ; i<max_ports; i++){
		if(port == allowed_ports[i]) return true;
	}
	return false;
}

static unsigned int ipv4_in_filter(
	void *priv,
	struct sk_buff *skb,
	const struct nf_hook_state *state
){
	struct iphdr *ip_header;
	struct tcphdr tcp_header;
	struct udphdr udp_header;
	unsigned short dst_port = 0;
	unsigned int header_offset;

	if(!skb) return NF_ACCEPT;
	ip_header = ip_hdr(skb);
	if (!ip_header) return NF_ACCEPT;
	if(ip_header->protocol == IPPROTO_ICMP){
		if (icmp_param == 1){
			printk_ratelimited(KERN_ALERT "icmp dropped\n");
			return NF_DROP;
		}
		return NF_ACCEPT;
	}
	if (ipv4_param == 0) return NF_ACCEPT;
	header_offset = ip_hdrlen(skb);
	if (ip_header->protocol == IPPROTO_TCP) {
		if (!skb_header_pointer(skb, header_offset, sizeof(tcp_header), &tcp_header)) return NF_DROP;

		dst_port = ntohs(tcp_header.dest);
	}
	else if (ip_header->protocol == IPPROTO_UDP) {
		if (!skb_header_pointer(skb, header_offset, sizeof(udp_header), &udp_header)) return NF_DROP;
		dst_port = ntohs(udp_header.dest);
	}
	else {
		printk_ratelimited(KERN_INFO "dropped incoming ipv4\n");
		return NF_DROP;
	}

	if (is_port_allowd(dst_port)) return NF_ACCEPT;

	return NF_DROP;
}

static unsigned int ipv6_in_filter(
	void *priv,
	struct sk_buff *skb,
	const struct nf_hook_state *state
)
{
	if (!skb) return NF_ACCEPT;
	if (ipv6_param == 1) return NF_DROP;
	return NF_ACCEPT;
}

static unsigned int ipv6_out_filter(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state
)
{
        if (!skb) return NF_ACCEPT;
        if (ipv6_param == 1) return NF_DROP;
        return NF_ACCEPT;
}

static int __init firewall_init(void){

	ipv4_in_hook.hook = ipv4_in_filter;
	ipv4_in_hook.pf = PF_INET;
	ipv4_in_hook.hooknum = NF_INET_LOCAL_IN;
	ipv4_in_hook.priority = NF_IP_PRI_FIRST;

	ipv6_in_hook.hook = ipv6_in_filter;
	ipv6_in_hook.pf = PF_INET6;
	ipv6_in_hook.hooknum = NF_INET_LOCAL_IN;
	ipv6_in_hook.priority = NF_IP6_PRI_FIRST;

	ipv6_out_hook.hook = ipv6_out_filter;
	ipv6_out_hook.pf = PF_INET6;
	ipv6_out_hook.hooknum = NF_INET_LOCAL_OUT;
	ipv6_out_hook.priority = NF_IP6_PRI_FIRST;
	
	nf_register_net_hook(&init_net, &ipv4_in_hook);
	nf_register_net_hook(&init_net, &ipv6_in_hook);
	nf_register_net_hook(&init_net, &ipv6_out_hook);
	printk(KERN_INFO "the caveman firewall has been loaded ho ho ho\n");

	return 0;
}

static void __exit firewall_exit(void)
{
	nf_unregister_net_hook(&init_net, &ipv6_out_hook);
	nf_unregister_net_hook(&init_net, &ipv6_in_hook);
	nf_unregister_net_hook(&init_net, &ipv4_in_hook);

	printk(KERN_INFO "the caveman firewall has been unloaded ho ho ho \n");
}
module_init(firewall_init);
module_exit(firewall_exit);
MODULE_AUTHOR("STARS");
MODULE_LICENSE("GPL");

