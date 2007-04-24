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
#ifndef _XT_PKNOCK_H
#define _XT_PKNOCK_H

#define MOD "xt_pknock: "

#define XT_PKNOCK_KNOCKPORT 		0x01
#define XT_PKNOCK_TIME  		0x02
#define XT_PKNOCK_NAME  		0x04
#define XT_PKNOCK_STRICT  		0x08
#define XT_PKNOCK_CHECKIP  		0x10
#define XT_PKNOCK_OPENSECRET  		0x20
#define XT_PKNOCK_CLOSESECRET  	0x40


#define XT_PKNOCK_MAX_PORTS 		15
#define XT_PKNOCK_MAX_BUF_LEN 		8
#define XT_PKNOCK_MAX_PASSWD_LEN 	32

#define DEBUG 1

struct xt_pknock_info {
	char		rule_name[XT_PKNOCK_MAX_BUF_LEN];
	int		rule_name_len;
	char		open_secret[XT_PKNOCK_MAX_PASSWD_LEN]; 
	int		open_secret_len;
	char		close_secret[XT_PKNOCK_MAX_PASSWD_LEN];
	int		close_secret_len;
	u_int8_t 	count_ports;		/* number of ports */
	u_int16_t 	port[XT_PKNOCK_MAX_PORTS]; /* port[,port,port,...] */
	unsigned long 	max_time;	/* max matching time between ports */
	u_int8_t 	option;		/* --time, --knock-port, ... */
};

struct xt_pknock_nl_msg {
	char			rule_name[XT_PKNOCK_MAX_BUF_LEN];
	u_int32_t 		peer_ip;
};

enum status {ST_INIT=1, ST_MATCHING, ST_ALLOWED};

#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/spinlock.h>

struct peer {
	struct list_head head;
	u_int32_t 	ip;
	u_int8_t	proto;
	u_int32_t 	id_port_knocked;
	enum status 	status;
	unsigned long 	timestamp;
	int		login_min; 	/* the login epoch minute */
};

#include <linux/proc_fs.h>

struct xt_pknock_rule {
	struct list_head 	head;
	char			rule_name[XT_PKNOCK_MAX_BUF_LEN];
	int			rule_name_len;
	unsigned int		ref_count;
	struct timer_list 	timer;		/* garbage collector timer */
	struct list_head 	*peer_head;
	struct proc_dir_entry  	*status_proc;
	unsigned long		max_time; /* max matching time between ports */
};


#include <linux/crypto.h>

struct xt_pknock_crypto {
	char 			*algo;
	struct crypto_tfm 	*tfm;
	int 			size;
};


struct transport_data {
	u_int8_t	proto;
	u_int16_t	port;
	int		payload_len;
	unsigned char	*payload;	
};

#endif /* __KERNEL__ */
#endif /* _XT_PKNOCK_H */
