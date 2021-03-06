#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linux/netlink.h>
#include <linux/connector.h>

#include "../../../../kernel/ipt_pknock.h"

#define GROUP 1

struct sockaddr_nl src_addr, dest_addr;
struct msghdr msg;
int sock_fd;

unsigned char *buf = NULL;

struct ipt_pknock_nl_msg *nlmsg;

int main() {
    socklen_t addrlen;
    int status;
    int group = GROUP; 
    struct cn_msg *cnmsg;
    
    int i, buf_size;
   
    char *ip;
    
    sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    
    if (sock_fd == -1) {
        perror("socket()");
        return 1;
    }
    
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;       
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = group;
    
    status = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    
    if (status == -1) {
        close(sock_fd);
        perror("bind()");
        return 1;
    }
    
    memset(&dest_addr, 0, sizeof(dest_addr)); 
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = group;
   
    buf_size = sizeof(struct ipt_pknock_nl_msg) + sizeof(struct cn_msg) + sizeof(struct nlmsghdr); 
    buf = (unsigned char *) malloc(buf_size);
    
    if (!buf) {
    	perror("malloc()");
        return 1;
    }
    
    addrlen = sizeof(dest_addr);
    
    while(1) {
        
        memset(buf, 0, buf_size);
        
        status = recvfrom(sock_fd, buf, buf_size, 0, (struct sockaddr *)&dest_addr, &addrlen);
        
        if (status <= 0) {
            perror("recvfrom()");
            return 1;
        }
        
	nlmsg = (struct ipt_pknock_nl_msg *) (buf + sizeof(struct cn_msg) + sizeof(struct nlmsghdr));

	ip = (char *)inet_ntoa((struct in_addr *) htonl(nlmsg->peer_ip));	
        printf("rule_name: %s - ip %s\n", nlmsg->rule_name, ip);
        
    }
    
    close(sock_fd);
    
    free(buf);

    return 0;
}    
