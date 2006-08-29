/*
 * Kernel module to implement port knocking matching support.
 * 
 * (C) 2006 J. Federico Hernandez <fede.hernandez@gmail.com>
 * (C) 2006 Luis Floreani <luis.floreani@gmail.com>
 *
 * $Id$
 *
 * This program is released under the terms of GNU GPL.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>	/* standard well-defined ip protocols */
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include <linux/netfilter_ipv4/ip_tables.h>
//#include <linux/netfilter_ipv4/ipt_pknock.h>
#include "ipt_pknock.h"

MODULE_AUTHOR("J. Federico Hernandez");
MODULE_DESCRIPTION("iptables/netfilter's port knocking match module");
MODULE_LICENSE("GPL");

#define EXPIRATION_TIME 50000 /* in msecs */

#define DEFAULT_RULE_HASH_SIZE 8
#define DEFAULT_PEER_HASH_SIZE 16

static u32 ipt_pknock_hash_rnd;

static unsigned int ipt_pknock_rule_htable_size = DEFAULT_RULE_HASH_SIZE;
static unsigned int ipt_pknock_peer_htable_size = DEFAULT_PEER_HASH_SIZE;

static struct list_head *rule_hashtable = NULL;

static DEFINE_SPINLOCK(rule_list_lock);
static struct proc_dir_entry *proc_net_ipt_pknock = NULL;

static char *the_secret = NULL;

/**
 * @key
 * @length
 * @initval
 * @max
 * @return: ?
 */
static u32 pknock_hash(const void *key, u32 length, u32 initval, u32 max) {
	return jhash(key, length, initval) % max;
}

/**
 * @size
 * return: hash
 */
static struct list_head *alloc_hashtable(int size) {
        struct list_head *hash = NULL;
        unsigned int i;

        if ((hash = kmalloc(sizeof(struct list_head) * size, GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in alloc_hashtable() function.\n");
		return NULL;
	}

        for (i = 0; i < size; i++)
        	INIT_LIST_HEAD(&hash[i]);
#if DEBUG
	printk(KERN_DEBUG MOD "%d buckets created. \n", size);
#endif				
        return hash;
}


#if DEBUG
/**
 * @iph
 */
static inline void print_ip_packet(struct iphdr *iph) {
	printk(KERN_INFO MOD "\nIP packet:\n"
		"VER=%d | IHL=%d | TOS=0x%02X | LEN=%d\n"
		"ID=%u | Flags | FRAG_OFF=%d\n"
		"TTL=%x | PROTO=%d | CHK=%d\n"
		"SRC=%u.%u.%u.%u\n"
		"DST=%u.%u.%u.%u\n", 
		iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len),
		ntohs(iph->id), iph->frag_off,
		iph->ttl, iph->protocol, ntohl(iph->check),
		NIPQUAD(iph->saddr), 
		NIPQUAD(iph->daddr));
}

/**
 * @info
 */
static inline void print_options(struct ipt_pknock_info *info) {
	int i;

	printk(KERN_INFO MOD "pknock options from kernel:\n"
		"count_ports: %d\ntime: %ld\noption: %d\n", 
		info->count_ports, info->max_time, info->option);
	
	for (i=0; i<info->count_ports; i++)
		printk(KERN_INFO MOD "port[%d]: %d\n", i, info->port[i]);
}

/**
 * @info
 */
static inline void print_list_peer(struct ipt_pknock_rule *rule) {
	struct list_head *pos = NULL;
	struct peer *peer = NULL;
	u_int32_t ip;

	if (list_empty(&rule->peer_head[0])) return;
	
	printk(KERN_INFO MOD "(*) %s list peer matching status:\n", rule->rule_name);
	
	list_for_each(pos, &rule->peer_head[0]) {
		peer = list_entry(pos, struct peer, head);
		ip = htonl(peer->ip);
		printk(KERN_INFO MOD "(*) peer: %u.%u.%u.%u - tstamp: %ld\n", 
					NIPQUAD(ip), peer->timestamp);
	}
}
#endif

/**
 * This function converts the status from integer to string.
 *
 * @status
 */
static inline const char *status_itoa(enum status status) {
	switch (status) {
	case ST_INIT: return "INIT";
	case ST_MATCHING: return "MATCHING";
	case ST_ALLOWED: return "ALLOWED";
	}
	return "UNKNOWN";
}

/**
 * This function produces the peer matching status data when the file is read.
 *
 * @buf
 * @start
 * @offset
 * @count
 * @eof
 * @data
 */
static int read_proc(char *buf, char **start, off_t offset, int count, int *eof, void *data) {
	int limit = count, len = 0, i;
	off_t pos = 0, begin = 0;
	u_int32_t ip;
	const char *status = NULL, *proto = NULL;
	struct list_head *p = NULL;
	struct ipt_pknock_rule *rule = NULL;
	struct peer *peer = NULL;
	unsigned long expiration_time = 0, max_time = 0;

	*eof=0;
	
	spin_lock_bh(&rule_list_lock);

	rule = (struct ipt_pknock_rule *)data;

	max_time = rule->max_time;

	for (i = 0; i < ipt_pknock_peer_htable_size; i++) {		
		list_for_each(p, &rule->peer_head[i]) {
			peer = list_entry(p, struct peer, head);
		
			status = status_itoa(peer->status);
		
			proto = (peer->proto == IPPROTO_TCP) ? "TCP" : "UDP";
			ip = htonl(peer->ip);
		
			expiration_time = ((jiffies/HZ) < (peer->timestamp + max_time)) ?
				((peer->timestamp+max_time)-(jiffies/HZ)) : 0;
			len += snprintf(buf+len, limit-len, "src=%u.%u.%u.%u ", NIPQUAD(ip));
			len += snprintf(buf+len, limit-len, "proto=%s ", proto);
			len += snprintf(buf+len, limit-len, "status=%s ", status);
			len += snprintf(buf+len, limit-len, "expiration_time=%ld ", 
				expiration_time);
			len += snprintf(buf+len, limit-len, "next_port_id=%d ",
				peer->id_port_knocked-1);
			len += snprintf(buf+len, limit-len, "\n");
		
			limit -= len;
			
			pos = begin + len;
			if(pos < offset) { len = 0; begin = pos; }
			if(pos > offset + count) { len = 0; break; }
		}

	}
	
	*start = buf + (offset - begin);
	len -= (offset - begin);
	if(len > count) len = count;
	*eof=1;
	
	spin_unlock_bh(&rule_list_lock);
	return len;
}

/**
 * Garbage collector. It removes the old entries after that the timer has expired.
 *
 * @r: rule
 */
static void peer_gc(unsigned long r) {
	struct ipt_pknock_rule *rule = (struct ipt_pknock_rule *)r;
	struct peer *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;

	if(timer_pending(&rule->timer) == 0) {
		if (list_empty(&rule->peer_head[0])) return;

		list_for_each_safe(pos, n, &rule->peer_head[0]) {
			peer = list_entry(pos, struct peer, head);

			if (peer->status == ST_ALLOWED || peer->status == ST_MATCHING) {
#if DEBUG
				printk(KERN_INFO MOD "(X) peer: %u.%u.%u.%u - DESTROYED\n",
					NIPQUAD(peer->ip));
#endif		
				list_del(pos);
				kfree(peer);
			}
		}
	}
}

/**
 * Si la regla existe en la lista, devuelve un puntero a la regla.
 *
 * @info
 * @return: rule or NULL
 */
static inline struct ipt_pknock_rule * search_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, ipt_pknock_hash_rnd, ipt_pknock_rule_htable_size);
	
	if (!list_empty(&rule_hashtable[hash])) {
		list_for_each_safe(pos, n, &rule_hashtable[hash]) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);
			
			if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) == 0)
				return rule;
		}		
	}

	return NULL;
}

/**
 * It adds a rule to list only if it doesn't exist.
 *
 * @info
 * @return: 1 success, 0 otherwise
 */
static int add_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL;
	
	int hash = pknock_hash(info->rule_name, info->rule_name_len, ipt_pknock_hash_rnd, ipt_pknock_rule_htable_size);

	if (!list_empty(&rule_hashtable[hash])) {
		list_for_each(pos, &rule_hashtable[hash]) {
			rule = list_entry(pos, struct ipt_pknock_rule, head);
			// If the rule exists.
			if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) == 0) {
				rule->ref_count++;
#if DEBUG
				printk(KERN_DEBUG MOD "add_rule() (E) rule found: %s - ref_count: %d\n", 
					rule->rule_name, rule->ref_count);
#endif				
				return 1;
			}
		}
	}
	// If it doesn't exist.
	if ((rule = (struct ipt_pknock_rule *)kmalloc(sizeof (*rule), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in add_rule() function.\n");
		return 0;
	}

	INIT_LIST_HEAD(&rule->head);
	strncpy(rule->rule_name, info->rule_name, info->rule_name_len);
	rule->ref_count	= 1;
	rule->max_time 	= info->max_time;
//	init_timer(&rule->timer);
//	rule->timer.expires 	= 0;
//	rule->timer.data	= (unsigned long)rule;
//	rule->timer.function 	= peer_gc;
//	add_timer(&rule->timer);
	
	rule->peer_head = alloc_hashtable(ipt_pknock_peer_htable_size);
	
	if (!(rule->status_proc = create_proc_read_entry(info->rule_name, 0, 
	proc_net_ipt_pknock, read_proc, rule))) {
		printk(KERN_ERR MOD "create_proc_entry() error in add_rule() function.\n");
		if (rule) kfree(rule);
		return 0;
	}

	list_add_tail(&rule->head, &rule_hashtable[hash]);
#if DEBUG
	printk(KERN_INFO MOD "(A) rule_name: %s - created.\n", rule->rule_name);
#endif	
	return 1;
	
}


/**
 * It removes a rule only if it exists.
 *
 * @info
 */
static void remove_rule(struct ipt_pknock_info *info) {
	struct ipt_pknock_rule *rule = NULL;
	struct list_head *pos = NULL, *n = NULL;
	struct peer *peer = NULL;
	int i, found = 0;

	int hash = pknock_hash(info->rule_name, info->rule_name_len, ipt_pknock_hash_rnd, ipt_pknock_rule_htable_size);
	
	if (list_empty(&rule_hashtable[hash])) return;

	list_for_each(pos, &rule_hashtable[hash]) {
		rule = list_entry(pos, struct ipt_pknock_rule, head);
		// If the rule exists.
		if (strncmp(info->rule_name, rule->rule_name, info->rule_name_len) == 0) {
			found = 1;
			rule->ref_count--;
			break;
		}
	}
#if DEBUG
	if (!found)
		printk(KERN_INFO MOD "(N) rule not found: %s.\n", info->rule_name);
#endif
	if (rule != NULL && rule->ref_count == 0) {
		for (i = 0; i < ipt_pknock_peer_htable_size; i++) {		
			list_for_each_safe(pos, n, &rule->peer_head[i]) {
				peer = list_entry(pos, struct peer, head);
				if (peer != NULL) {
#if DEBUG	
					printk(KERN_INFO MOD "(D) peer deleted: %u.%u.%u.%u\n", 
					NIPQUAD(peer->ip));
#endif				
					list_del(pos);
					kfree(peer);
				}
			}
		}
		if (rule->status_proc) remove_proc_entry(info->rule_name, proc_net_ipt_pknock);
#if DEBUG
		printk(KERN_INFO MOD "(D) rule deleted: %s.\n", rule->rule_name);
#endif
//		if (timer_pending(&rule->timer))
//		del_timer(&rule->timer);
				
		list_del(&rule->head);
		kfree(rule);
	}

}

/**
 * It updates the rule timer to execute garbage collector.
 *
 * @rule
 */
static inline void update_rule_timer(struct ipt_pknock_rule *rule) {
	rule->timer.expires = jiffies + msecs_to_jiffies(EXPIRATION_TIME);
	add_timer(&rule->timer);
}

/**
 * If peer status exist in the list it returns peer status, if not it returns NULL.
 *
 * @rule
 * @ip
 * @return: peer or NULL
 */
static inline struct peer * get_peer(struct ipt_pknock_rule *rule, u_int32_t ip) {
	struct peer *peer = NULL;
	struct list_head *pos = NULL, *n = NULL;
	int hash;

	ip = ntohl(ip);
	
	hash = pknock_hash(&ip, sizeof(u_int32_t), ipt_pknock_hash_rnd, ipt_pknock_peer_htable_size);
#if DEBUG
//	printk(KERN_DEBUG MOD "get_peer() -> hash %d \n", hash);
#endif				
	if (list_empty(&rule->peer_head[hash])) return NULL;
	
	list_for_each_safe(pos, n, &rule->peer_head[hash]) {
		peer = list_entry(pos, struct peer, head);
		if (peer->ip == ip) return peer;
	}
	return NULL;
}

/**
 * It creates a new peer matching status.
 *
 * @rule
 * @ip
 * @proto
 * @return: peer or NULL
 */
static inline struct peer * new_peer(u_int32_t ip, u_int8_t proto) {
	struct peer *peer = NULL;

	if ((peer = (struct peer *)kmalloc(sizeof (*peer), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in new_peer() function.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&peer->head);
	peer->ip 	= ntohl(ip);
	peer->proto 	= proto;
	peer->status 	= ST_INIT;
	peer->timestamp = jiffies/HZ;
	peer->id_port_knocked = 0;

	return peer;
}

/**
 * It adds a new peer matching status to the list.
 *
 * @peer
 * @rule
 */
static inline void add_peer(struct peer *peer, struct ipt_pknock_rule *rule) {
	int hash = pknock_hash(&peer->ip, sizeof(u_int32_t), 
			ipt_pknock_hash_rnd, ipt_pknock_peer_htable_size);
#if DEBUG
	printk(KERN_DEBUG MOD "add_peer() -> hash %d \n", hash);
#endif				
	list_add_tail(&peer->head, &rule->peer_head[hash]);
	
	peer->timestamp = jiffies/HZ;
	peer->status = ST_MATCHING;
	peer->id_port_knocked = 1;
}

/**
 * It removes a peer matching status.
 *
 * @peer
 */
static inline void remove_peer(struct peer *peer) {
	list_del(&peer->head);
	if (peer) kfree(peer);
}

#define IS_FIRST_KNOCK(peer, info, port) ((peer) == NULL && (((info)->port[0] == (port)) ? 1 : 0))
#define IS_WRONG_KNOCK(peer, info, port) (((info)->port[(peer)->id_port_knocked-1]) != (port))
#define IS_LAST_KNOCK(peer, info) ((peer)->id_port_knocked-1 == (info)->count_ports)
#define IS_ALLOWED(peer) ((peer) && ((peer)->status == ST_ALLOWED) ? 1 : 0)

/**
 * It updates the peer matching status.
 *
 * @peer
 * @info
 * @port
 * @return: 1 if allowed, 0 otherwise
 */
static int update_peer(struct peer *peer, struct ipt_pknock_info *info, u_int16_t port) {
	unsigned long time;
	
	if (IS_ALLOWED(peer)) {
#if DEBUG
		printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - PASS OK.\n", NIPQUAD(peer->ip));
#endif
		return 1;
	}
	
	if (IS_WRONG_KNOCK(peer, info, port)) {
#if DEBUG
		printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - DIDN'T MATCH.\n", NIPQUAD(peer->ip));
#endif
		return 0;
	}

	peer->id_port_knocked++;
	
	if (IS_LAST_KNOCK(peer, info)) {
		peer->status = ST_ALLOWED;
#if DEBUG
		printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - ALLOWED.\n", NIPQUAD(peer->ip));	
#endif
		return 0;
	}

	/* 
	 * Controls the max matching time between ports.
	 */
	if (info->option & IPT_PKNOCK_TIME) {
		time = jiffies/HZ;
		
		if (time > (peer->timestamp + info->max_time)) {
#if DEBUG
			printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - TIME EXCEEDED.\n", NIPQUAD(peer->ip));
			printk(KERN_INFO MOD "(X) peer: %u.%u.%u.%u - DESTROYED.\n", NIPQUAD(peer->ip));
			printk(KERN_INFO MOD "max_time: %ld - time: %ld\n", 
				peer->timestamp + info->max_time, time);
#endif
			remove_peer(peer);
			return 0;
		}
		peer->timestamp = time;		
	}
#if DEBUG
	printk(KERN_INFO MOD "(S) peer: %u.%u.%u.%u - MATCHING.\n", 
		NIPQUAD(peer->ip));
#endif
	return 0;
}

static void hexdump(unsigned char *buf, unsigned int len /*md5: 16*/) {
	while (len--)
		printk("%02x", *buf++);
	printk("\n");
}

static int has_secret(unsigned char *secret, u_int32_t ipsrc, unsigned char *payload, int payload_len) {
	char *algo = "md5";

	struct scatterlist sg[2];
        char result[64];
        struct crypto_tfm *tfm;
	int hashbytes = 16;
	
	if (payload_len != hashbytes) {
		return 0;
	}

	tfm = crypto_alloc_tfm(algo, 0);	

        if (tfm == NULL) {
		printk(KERN_INFO MOD "failed to load transform for %s\n", algo);
		return 0;
	}
	
	memset(result, 0, 64);

	sg_set_buf(&sg[0], secret, strlen(secret));
	sg_set_buf(&sg[1], &ipsrc, sizeof(u_int32_t));
	
        crypto_digest_init(tfm);
        crypto_digest_update(tfm, (void *)&sg[0], 2);
        crypto_digest_final(tfm, result);

	//hexdump(result, crypto_tfm_alg_digestsize(tfm));	
	printk("md5 hash size %d\n", crypto_tfm_alg_digestsize(tfm));
	
	if (memcmp(result, payload, crypto_tfm_alg_digestsize(tfm)) != 0) { 
#if DEBUG
		printk(KERN_INFO MOD "payload len: %d\n", payload_len);
		printk(KERN_INFO MOD "secret match failed\n");
#endif
		crypto_free_tfm(tfm);
		return 0;
	}
	
	crypto_free_tfm(tfm);	
	return 1;
}


static int match(const struct sk_buff *skb,
	      const struct net_device *in,
	      const struct net_device *out,
	      const void *matchinfo,
	      int offset,
	      int *hotdrop) 
{
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)matchinfo;
	struct ipt_pknock_rule *rule = NULL;
	struct peer *peer = NULL;
	struct iphdr *iph = skb->nh.iph;
	int iphl = iph->ihl * 4;
	void *transph = (void *)iph + iphl;		/* tranport protocol header */
	u_int16_t port = 0;
	u_int8_t proto = 0;
	int ret=0;	
	unsigned char *payload;
	int payload_len;
	int headers_len;

	switch ((proto = iph->protocol)) {
	case IPPROTO_TCP:
		port = ntohs(((struct tcphdr *)transph)->dest); 
		headers_len = iphl + sizeof(struct tcphdr);
		break;
	
	case IPPROTO_UDP:
		port = ntohs(((struct udphdr *)transph)->dest);
		headers_len = iphl + sizeof(struct udphdr);
		break;
	
	default:
		printk(KERN_INFO MOD "IP payload protocol is neither tcp nor udp.\n");
		goto end;
	}

	spin_lock_bh(&rule_list_lock);

	/* 
	 * Searches a rule from the list depending on info structure options.
	 */
	if ((rule = search_rule(info)) == NULL) {
		printk(KERN_INFO MOD "The rule %s doesn't exist.\n", info->rule_name);
		goto end;
	}
	/*
	 * Updates the rule timer to execute the garbage collector.
	 */
//	update_rule_timer(rule);
	/* 
	 * Gives the peer matching status added to rule depending on ip source.
	 */
	peer = get_peer(rule, iph->saddr);
	/*
	 * Sets, adds, removes or checks the peer matching status.
	 */
	
	/* If security is needed and the peer is still knocking ... */
	if ((info->option & IPT_PKNOCK_SECURE) && !IS_ALLOWED(peer)) {
		if (!the_secret) {
			printk(KERN_INFO MOD "FAIL: The secret has not been initialized.\n");
			goto end;
		}
		payload = (void *)iph + headers_len;
		payload_len = skb->len - headers_len;
		if (!has_secret(the_secret, iph->saddr, payload, payload_len))
			goto end;
	}
	
	if (info->option & IPT_PKNOCK_KNOCKPORT) {
		if (IS_FIRST_KNOCK(peer, info, port)) {
			peer = new_peer(iph->saddr, proto);
			add_peer(peer, rule);
		} 
		
		if (peer != NULL) {
			ret = update_peer(peer, info, port);
			goto end;
		}
	}

end:
	spin_unlock_bh(&rule_list_lock);
	return ret;
}

static int checkentry(const char *tablename,
			const struct ipt_ip *ip,
			void *matchinfo,
			unsigned int matchinfosize,
			unsigned int hook_mask) 
{
	struct ipt_pknock_info *info = (struct ipt_pknock_info *)matchinfo;
	
	if (matchinfosize != IPT_ALIGN(sizeof (*info)))
		return 0;

	if (!rule_hashtable) {
		rule_hashtable = alloc_hashtable(ipt_pknock_rule_htable_size);
		get_random_bytes(&ipt_pknock_hash_rnd, sizeof(u32));
	}
	
	if (!add_rule(info)) {
		printk(KERN_ERR MOD "add_rule() error in checkentry() function.\n");
		return 0;
	}
	return 1;
}

static void destroy(void *matchinfo, unsigned int matchinfosize) 
{
	struct ipt_pknock_info *info = (void *)matchinfo;
	/* 
	 * Removes a rule only if it exits and ref_count is equal to 0.
	 */
	remove_rule(info);
}

static struct ipt_match ipt_pknock_match = {
	.name 		= "pknock",
	.match 		= match,
	.checkentry 	= checkentry,
	.destroy	= destroy,
	.me 		= THIS_MODULE
};

static int set_rule_hashsize(const char *val, struct kernel_param *kp) {
        int hashsize;
	
        hashsize = simple_strtol(val, NULL, 0);
        
	if (!hashsize)
                return -EINVAL;

	ipt_pknock_rule_htable_size = hashsize;
				
	return 0;
}

static int set_peer_hashsize(const char *val, struct kernel_param *kp) {
        int hashsize;
	
        hashsize = simple_strtol(val, NULL, 0);
        
	if (!hashsize)
                return -EINVAL;

	ipt_pknock_peer_htable_size = hashsize;
				
	return 0;
}	

static int set_secret(const char *buffer, struct kernel_param *kp) {
	int size = strlen(buffer);

	if (size < 5) {
		printk(KERN_ERR MOD "secret size too short (min len = 5).\n");
	        return -EINVAL;
	}	

        if ((the_secret = kmalloc(sizeof(char) * size, GFP_KERNEL)) == NULL) {
		printk(KERN_ERR MOD "kmalloc() error in set_secret() function.\n");
		return -EINVAL;
	}
	
	memset(the_secret, 0, size);

	strcpy(the_secret, buffer);

	return 0;
}

module_param_call(rule_hashsize, set_rule_hashsize, param_get_uint, &ipt_pknock_rule_htable_size, 0600);
module_param_call(peer_hashsize, set_peer_hashsize, param_get_uint, &ipt_pknock_peer_htable_size, 0600);
module_param_call(secret, set_secret, NULL, NULL, 0600);


static int __init init(void) 
{
	printk(KERN_INFO MOD "register.\n");

	if (!(proc_net_ipt_pknock = proc_mkdir("ipt_pknock", proc_net))) {
		printk(KERN_ERR MOD "proc_mkdir() error in function init().\n");
		return -1;
	}
	return ipt_register_match(&ipt_pknock_match);
}

static void __exit fini(void)
{
	printk(KERN_INFO MOD "unregister.\n");
	remove_proc_entry("ipt_pknock", proc_net);
	ipt_unregister_match(&ipt_pknock_match);
}

module_init(init);
module_exit(fini);
