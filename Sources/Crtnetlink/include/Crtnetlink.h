#ifndef CRTLINK_H
#define CRTLINK_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/prctl.h>
#include <linux/capability.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Open a netlink route socket bound to this process. Returns a socket fd, or
 * -1 on failure. Caller must close() it. */
int open_netlink(void);

/* --- interface related --- */
/* request the full interface dump */
int do_interface_dump_request(int sock);
/* receive + iterate the dump, invoking hndlr per RTM_NEWLINK message */
int get_interface_dump_response(int sock, void (^hndlr)(struct nlmsghdr *));
/* interpret a single RTM_NEWLINK message into a struct ifinfomsg + attrs */
int read_interface(struct nlmsghdr *nl_header_answer, void (^hndlr)(struct ifinfomsg *ifin, struct rtattr *attrs[IFLA_MAX + 1]));
/* format the IFLA_ADDRESS / IFLA_BROADCAST MAC attribute into a string */
void get_attribute_data_ifla(struct rtattr *attrs[IFLA_MAX + 1], int attrKey, char **buf);

/* --- address related --- */
int do_address_dump_request_v4(int sock);
int do_address_dump_request_v6(int sock);
int get_address_dump_response(int sock, void (^hndlr)(struct nlmsghdr *));
int read_address(struct nlmsghdr *, void (^hndlr)(struct ifaddrmsg *ifa, struct rtattr *attrs[IFA_MAX + 1]));
void get_attribute_data_ifa(unsigned char family, struct rtattr *attrs[IFA_MAX + 1], int attrKey, char **buf);
int get_attribute_uint32_ifa(struct rtattr *attrs[IFA_MAX + 1], int attrKey, uint32_t *num);

/* --- route related --- */
int do_route_dump_request_v4(int sock);
int do_route_dump_request_v6(int sock);
int get_route_dump_response(int sock, void (^hndlr)(struct nlmsghdr *));
int read_route(struct nlmsghdr *, void (^hndlr)(struct rtmsg *r, struct rtattr *tb[RTA_MAX + 1]));
void get_attribute_data_rt(unsigned char family, struct rtattr *attrs[RTA_MAX + 1], enum rtattr_type_t attrKey, char **buf);
int get_attribute_uint32_rt(struct rtattr *attrs[RTA_MAX + 1], enum rtattr_type_t attrKey, uint32_t *num);

/* Raise CAP_NET_ADMIN into the ambient set so child processes inherit it. */
int raise_ambient_cap_net_admin(void);

#ifdef __cplusplus
}
#endif

#endif /* CRTLINK_H */