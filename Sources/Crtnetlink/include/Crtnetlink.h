#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

// typedef struct nl_request {
// 	struct nlmsghdr nlh;
// 	struct rtmsg rtm;
// } nl_request;

int open_netlink();

// interface related functions
// - sending
int do_interface_dump_request(int sock);
// - receiving
int get_interface_dump_response(int sock, void(^hndlr)(struct nlmsghdr *));
// - interpreting
int read_interface(struct nlmsghdr *nl_header_answer, void(^hndlr)(struct ifinfomsg *ifin, struct rtattr *attrs[RTA_MAX+1]));
// - attributes
void get_attribute_data_ifla(unsigned char family, struct rtattr *attrs[IFLA_MAX+1], int attrKey, char **buf);


// address related functions
// - sending
int	do_address_dump_request_v4(int sock);
int do_address_dump_request_v6(int sock);
// - receiving
int get_address_dump_response(int sock, void(^hndlr)(struct nlmsghdr *));
// - interpreting
int read_address(struct nlmsghdr *, void(^hndlr)(struct ifaddrmsg *ifa, struct rtattr *attrs[RTA_MAX+1]));
// - attributes
void get_attribute_data_ifa(unsigned char family, struct rtattr *attrs[IFA_MAX+1], int attrKey, char **buf);

// route related functions
// - sending
int do_route_dump_request_v4(int sock);
int do_route_dump_request_v6(int sock);
// - receiving
int get_route_dump_response(int sock, void(^hndlr)(struct nlmsghdr *));
// - interpreting
int read_route(struct nlmsghdr *, void(^hndlr)(struct rtmsg *r, struct rtattr *tb[RTA_MAX+1]));
// - attributes
void get_attribute_data_rt(unsigned char family, struct rtattr *attrs[RTA_MAX+1], enum rtattr_type_t attrKey, char **buf);
int get_attribute_uint32_rt(struct rtattr *attrs[RTA_MAX+1], enum rtattr_type_t attrKey, uint32_t *num);

