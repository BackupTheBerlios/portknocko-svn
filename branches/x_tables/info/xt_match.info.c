struct xt_match
{
	struct list_head list;

	const char name[XT_FUNCTION_MAXNAMELEN-1];

	/* Return true or false: return FALSE and set *hotdrop = 1 to
           force immediate packet drop. */
	/* Arguments changed since 2.6.9, as this must now handle
	   non-linear skb, using skb_header_pointer and
	   skb_ip_make_writable. */
	int (*match)(const struct sk_buff *skb,
		     const struct net_device *in,
		     const struct net_device *out,
		     const struct xt_match *match,
		     const void *matchinfo,
		     int offset,
		     unsigned int protoff,
		     int *hotdrop);

	/* Called when user tries to insert an entry of this type. */
	/* Should return true or false. */
	int (*checkentry)(const char *tablename,
			  const void *ip,
			  const struct xt_match *match,
			  void *matchinfo,
			  unsigned int matchinfosize,
			  unsigned int hook_mask);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_match *match, void *matchinfo,
			unsigned int matchinfosize);

	/* Called when userspace align differs from kernel space one */
	int (*compat)(void *match, void **dstptr, int *size, int convert);

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	char *table;
	unsigned int matchsize;
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
	u_int8_t revision;
};

