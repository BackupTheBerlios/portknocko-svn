/*
 * Shared library add-on to iptables to add port knocking matching support.
 *
 * (C) 2006 J. Federico Hernandez <fede.hernandez@gmail.com>
 * (C) 2006 Luis Floreani <luis.floreani@gmail.com>
 *
 * $Id$
 *
 * This program is released under the terms of GNU GPL.
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <iptables.h>
//#include <linux/netfilter_ipv4/xt_pknock.h>
#include "../kernel/xt_pknock.h"

static struct option opts[] = {
	{ .name = "knockports", .has_arg = 1,	.flag = 0,	.val = 'k' },
	{ .name = "t",		.has_arg = 1, 	.flag = 0, 	.val = 't' },
	{ .name = "time",	.has_arg = 1, 	.flag = 0,	.val = 't' }, /* synonym */
	{ .name = "name", 	.has_arg = 1, 	.flag = 0, 	.val = 'n' },
	{ .name = "secure", 	.has_arg = 0, 	.flag = 0, 	.val = 's' },
	{ .name = 0 }
};

static void help(void) {
	printf("Port Knocking match v%s options:\n"
		" --knockports port[,port,port,...] 	Matches destination port(s).\n"
		" --time seconds\n"
		" --t ...				Time between port match.\n"
		" [--secure] 				hmac must be in the packets.\n"
		" --name rule_name			Rule name.\n", IPTABLES_VERSION);
}

/*
 * Se llama al cargarse el m�dulo. Inicializa el match (se setean
 * valores por defecto y el cacheo de netfilter.
 */
static void init(struct xt_entry_match *m, unsigned int *nfcache) {
	*nfcache |= NFC_UNKNOWN;
}

/*
 * parse_ports():
 *
 * Parsea ports por comas (ej. de ports: "4000,1000,2000"), los 
 * convierte a entero y los devuelve en port_buf.
 *
 * @param const char *ports	number of ports
 * @param u_int16_t *port_buf
 * @param u_int8_t *count	count ports
 * @return			0 success, > 0 otherwise
 */
static int parse_ports(const char *ports, u_int16_t *port_buf, u_int8_t *count) {
	char *token=NULL, *str=NULL;
	const char *delim = ",";
	int i;
	
	if (ports == NULL) return 1;

	if ((str = strdup(ports)) == NULL) return 2;

	for (i=0, token = strtok(str, delim); token != NULL && i < XT_PKNOCK_MAX_PORTS; 
	token = strtok(NULL, delim), i++, port_buf++) {
		if (string_to_number(token, 0, 65535, (unsigned int *)port_buf) == -1) {
			if (str) free(str);
			return 3;
		}
#if DEBUG
		printf("port[%d]: %d\n", i, *port_buf);
#endif
	}
	*count = i;

	if (str) free(str);
	return 0;
}

#define EXIT_ERR_REPORT(error_val) do { 						\
	switch (error_val) {								\
	case 1:										\
		fprintf(stderr, "%s port[,port,port,...]\n", argv[0]); break;		\
	case 2:										\
		fprintf(stderr, "There isn't enough memory - strdup().\n"); break; 	\
	case 3:										\
		fprintf(stderr, "Port number invalid.\n"); break;			\
	}										\
	exit(EXIT_FAILURE);								\
} while (0)										\

/*
 * parse()
 *
 * Parsea la l�nea de comandos. Devuelve true si encuentra una opci�n.
 * Es llamada cada vez que se encuentra un argumento.
 *
 * @param integer c - c�digo del argumento
 * @param struct xt_entry_match *match - contiene los argumentos, es compartida con el espacio de kernel.
 *
 * @return integer - 1 if option is found, 0 otherwise
 */
static int parse(int c, char **argv, int invert, unsigned int *flags, 
		const struct xt_entry *entry, 
		unsigned int *nfcache, 
		struct xt_entry_match **match) {
	struct xt_pknock_info *info = (struct xt_pknock_info *) (*match)->data;
	int ret=0;

/*** VERIFICAR en cada opci�n el inverso (!). */
	
	switch (c) {
	case 'k': /* --knockports */
		if (*flags & XT_PKNOCK_KNOCKPORT)
			exit_error(PARAMETER_PROBLEM, MOD "Cant't use --knockports twice.\n");
		
		if ((ret = parse_ports(optarg, info->port, &(info->count_ports))) != 0) 
			EXIT_ERR_REPORT(ret);
#if DEBUG
		printf("count_ports: %d\n", info->count_ports);
#endif
		*flags |= XT_PKNOCK_KNOCKPORT;
		info->option |= XT_PKNOCK_KNOCKPORT;
		break;
		
	case 't': /* --time */
		if (*flags & XT_PKNOCK_TIME)
			exit_error(PARAMETER_PROBLEM, MOD "Cant't use --time twice.\n");
		
		info->max_time = atoi(optarg);	
		
		*flags |= XT_PKNOCK_TIME;
		info->option |= XT_PKNOCK_TIME;
		break;
		
	case 'n': /* --name */
		if (*flags & XT_PKNOCK_NAME)
			exit_error(PARAMETER_PROBLEM, MOD "Can't use --name twice.\n");
	
		strncpy(info->rule_name, optarg, XT_PKNOCK_MAX_BUF_LEN);		
		info->rule_name_len = strlen(info->rule_name);
#if DEBUG
		printf("info->rule_name: %s\n", info->rule_name);
#endif
		*flags |= XT_PKNOCK_NAME;
		info->option |= XT_PKNOCK_NAME;
		break;
	
	case 's': /* --secure */
		if (*flags & XT_PKNOCK_SECURE)
			exit_error(PARAMETER_PROBLEM, MOD "Can't use --secure twice.\n");
		*flags |= XT_PKNOCK_SECURE;
		info->option |= XT_PKNOCK_SECURE;
		break;

		
	default:
		return 0;
	}
	return 1;
}

/*
 * Esta funci�n da una �ltima oportunidad de verificar las reglas. Es llamada despu�s
 * del parseo de los argumentos.
 */
static void final_check(unsigned int flags) { 
	if (!flags)
		exit_error(PARAMETER_PROBLEM, MOD "you must specify an option.\n");
}

/*
 * Imprime informaci�n sobre la regla. Es llamada por "iptables -L".
 */
static void print(const struct xt_ip *ip, const struct xt_entry_match *match, int numeric) {
	const struct xt_pknock_info *info = (const struct xt_pknock_info *)match->data;
	int i;
	
	printf("pknock ");
	if (info->option & XT_PKNOCK_KNOCKPORT) {
		printf("knockports ");
		for (i=0; i<info->count_ports; i++)
			printf("%s%d", i ? "," : "", info->port[i]);
		printf(" ");
	}
	if (info->option & XT_PKNOCK_TIME) printf("time %ld ", info->max_time);
	if (info->option & XT_PKNOCK_NAME) printf("name %s ", info->rule_name);
	if (info->option & XT_PKNOCK_SECURE) printf("secure ");
}

/*
 * Esta funci�n muestra por pantalla todos los argumentos de una regla determinada. Estos 
 * argumentos est�n almacenados en la estructura xt_entry_match que identifica a una regla.
 * Es llamada cuando se usa "iptables-save".
 */
static void save(const struct xt_ip *ip, const struct xt_entry_match *match) {
	const struct xt_pknock_info *info = (const struct xt_pknock_info *)match->data;
	int i;
	
	if (info->option & XT_PKNOCK_KNOCKPORT) {
		printf("--knockports ");
		for (i=0; i<info->count_ports; i++)
			printf("%s%d", i ? "," : "", info->port[i]);
		printf(" ");
	}
	if (info->option & XT_PKNOCK_TIME) printf("--time %ld ", info->max_time);
	if (info->option & XT_PKNOCK_NAME) printf("--name %s ", info->rule_name);
	if (info->option & XT_PKNOCK_NAME) printf("--secure ");
}


static struct iptables_match pknock = {
	.name 		= "pknock",
	.version 	= IPTABLES_VERSION,
	.size		= XT_ALIGN(sizeof (struct xt_pknock_info)),
	.userspacesize	= XT_ALIGN(sizeof (struct xt_pknock_info)),
	.help		= &help,
	.init		= &init,
	.parse		= &parse,
	.final_check	= &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts	= opts
};


void _init(void) {
	register_match(&pknock);
}

