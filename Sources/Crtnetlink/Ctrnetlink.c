#include "Crtnetlink.h"

static int rtnl_receive(int fd, struct msghdr *msg, int flags)
{
    int len;

    do { 
        len = recvmsg(fd, msg, flags);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len < 0) {
        perror("Netlink receive failed");
        return -errno;
    }

    if (len == 0) { 
        perror("EOF on netlink");
        return -ENODATA;
    }

    return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf;
    int len;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    len = rtnl_receive(fd, msg, MSG_PEEK | MSG_TRUNC);

    if (len < 0) {
        return len;
    }

    buf = malloc(len);

    if (!buf) {
        return -ENOMEM;
    }

    iov->iov_base = buf;
    iov->iov_len = len;

    len = rtnl_receive(fd, msg, 0);

    if (len < 0) {
        free(buf);
        return len;
    }

    *answer = buf;

    return len;
}

static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		}

		rta = RTA_NEXT(rta,len);
	}
}

int do_interface_dump_request(int sock) {
	// construct
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} request;
	request.nlh.nlmsg_type = RTM_GETLINK;
	request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nlh.nlmsg_len = sizeof(request);
	request.nlh.nlmsg_seq = time(NULL);
	// send
	return send(sock, &request, sizeof(request), 0);
}

int get_interface_dump_response(int sock, void(^hndlr)(struct nlmsghdr *)) {
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    // 64KB is standard and safely holds a single netlink packet
    char buf[65536];
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    while (1) {
        int len = rtnl_receive(sock, &msg, 0);
        if (len < 0) return (int)len; // Socket error

        struct nlmsghdr *h = (struct nlmsghdr*)buf;
        int msglen = len;

        while (NLMSG_OK(h, msglen)) {
            if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
                return -1; // Dump interrupted by kernel
            }
            if (nladdr.nl_pid != 0) {
                h = NLMSG_NEXT(h, msglen);
                continue;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                return -2; // Kernel returned error
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                return 0; // ✅ Dump complete
            }
            // Only process interface link messages
            if (h->nlmsg_type == RTM_NEWLINK) {
                hndlr(h);
            }
            h = NLMSG_NEXT(h, msglen);
        }
        // Finished this packet. Continue recvmsg() for the next one.
    }
}

int read_interface(struct nlmsghdr *nl_header_answer, void(^hndlr)(struct ifinfomsg *ifin, struct rtattr *attrs[IFLA_MAX+1])) {
    if (nl_header_answer->nlmsg_type != RTM_NEWLINK) {
        return -1;
    }

    struct ifinfomsg *ifin = NLMSG_DATA(nl_header_answer);
    int len = nl_header_answer->nlmsg_len;
    struct rtattr *tb[IFLA_MAX+1];

    len -= NLMSG_LENGTH(sizeof(*ifin));
    if (len < 0) return -1;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifin), len);

    hndlr(ifin, tb);
    return 0;
}

void get_attribute_data_ifla(unsigned char family, struct rtattr *attrs[IFLA_MAX+1], int attrKey, char **buf) {
	if (attrs[attrKey]) {
		unsigned char *newBuff = (unsigned char*)RTA_DATA(attrs[attrKey]);
		(*buf) = malloc(32);
		snprintf((*buf), 32, "%02x:%02x:%02x:%02x:%02x:%02x", newBuff[0], newBuff[1], newBuff[2], newBuff[3], newBuff[4], newBuff[5]);
	} else {
		*buf = NULL;
	}
}

int do_address_dump_request_v4(int sock) {
	// construct
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} request;
	request.nlh.nlmsg_type = RTM_GETADDR;
	request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nlh.nlmsg_len = sizeof(request);
	request.nlh.nlmsg_seq = time(NULL);
	request.rtm.rtm_family = AF_INET;
	// send
	return send(sock, &request, sizeof(request), 0);
}

int do_address_dump_request_v6(int sock) {
	// construct
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm
	} request;
	request.nlh.nlmsg_type = RTM_GETADDR;
	request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nlh.nlmsg_len = sizeof(request);
	request.nlh.nlmsg_seq = time(NULL);
	request.rtm.rtm_family = AF_INET6;
	// send
	return send(sock, &request, sizeof(request), 0);

}

int get_address_dump_response(int sock, void(^hndlr)(struct nlmsghdr *)) {
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = { .msg_name = &nladdr, .msg_namelen = sizeof(nladdr), .msg_iov = &iov, .msg_iovlen = 1 };
    char buf[65536];
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    while (1) {
        int len = rtnl_receive(sock, &msg, 0);
        if (len < 0) return (int)len;
        struct nlmsghdr *h = (struct nlmsghdr*)buf;
        int msglen = len;
        while (NLMSG_OK(h, msglen)) {
            if (h->nlmsg_flags & NLM_F_DUMP_INTR) return -1;
            if (nladdr.nl_pid != 0) { h = NLMSG_NEXT(h, msglen); continue; }
            if (h->nlmsg_type == NLMSG_ERROR) return -2;
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == RTM_NEWADDR) hndlr(h);
            h = NLMSG_NEXT(h, msglen);
        }
    }
}

int read_address(struct nlmsghdr *nl_header_answer, void(^hndlr)(struct ifaddrmsg *ifa, struct rtattr *attrs[RTA_MAX+1])) {
	struct ifaddrmsg *ifa = NLMSG_DATA(nl_header_answer);
	int len = nl_header_answer->nlmsg_len;
	struct rtattr *tb[IFA_MAX+1];
	char buf[256];
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) {
		return -1;
	}
	
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);
	
	hndlr(ifa, tb);
	return 0;
}

void get_attribute_data_ifa(unsigned char family, struct rtattr *attrs[IFA_MAX+1], int attrKey, char **buf) {
	if (attrs[attrKey]) {
		char *newBuff = malloc(256);
		inet_ntop(family, RTA_DATA(attrs[attrKey]), newBuff, 256);
		(*buf) = newBuff;
	} else {
		*buf = NULL;
	}
}

int open_netlink()
{
    struct sockaddr_nl saddr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind to netlink socket");
        close(sock);
        return -1;
    }

    return sock;
}

int do_route_dump_request_v4(int sock)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } nl_request;

    nl_request.nlh.nlmsg_type = RTM_GETROUTE;
    nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_request.nlh.nlmsg_len = sizeof(nl_request);
    nl_request.nlh.nlmsg_seq = time(NULL);
    nl_request.rtm.rtm_family = AF_INET;

    return send(sock, &nl_request, sizeof(nl_request), 0);
}

int do_route_dump_request_v6(int sock)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } nl_request;

    nl_request.nlh.nlmsg_type = RTM_GETROUTE;
    nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_request.nlh.nlmsg_len = sizeof(nl_request);
    nl_request.nlh.nlmsg_seq = time(NULL);
    nl_request.rtm.rtm_family = AF_INET6;

    return send(sock, &nl_request, sizeof(nl_request), 0);
}


int get_route_dump_response(int sock, void(^hndlr)(struct nlmsghdr*))
{
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    char *buf;
    int dump_intr = 0;

    int status = rtnl_recvmsg(sock, &msg, &buf);

    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int msglen = status;
    while (NLMSG_OK(h, msglen)) {
        if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
            free(buf);
            return -1;
        }

        if (nladdr.nl_pid != 0) {
            continue;
        }

        if (h->nlmsg_type == NLMSG_ERROR) {
            perror("netlink reported error");
            free(buf);
        }

        hndlr(h);

        h = NLMSG_NEXT(h, msglen);
    }

    free(buf);

    return status;
}

int read_route(struct nlmsghdr *nl_header_answer, void(^hndlr)(struct rtmsg *r, struct rtattr *tb[RTA_MAX+1])) {
    struct rtmsg* r = NLMSG_DATA(nl_header_answer);
    int len = nl_header_answer->nlmsg_len;
    struct rtattr* tb[RTA_MAX+1];
    char buf[256];

    len -= NLMSG_LENGTH(sizeof(*r));
    
    if (len < 0) {
        return -1;
    }

    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	
	hndlr(r, tb);
	return 0;
}

void get_attribute_data_rt(unsigned char family, struct rtattr *attrs[RTA_MAX+1], enum rtattr_type_t attrKey, char **buf) {
	if (attrs[attrKey]) {
		char *newBuff = malloc(256);
		inet_ntop(family, RTA_DATA(attrs[attrKey]), newBuff, 256);
		(*buf) = newBuff;
	} else {
		*buf = NULL;
	}
}

int get_attribute_uint32_rt(struct rtattr* attrs[RTA_MAX+1], enum rtattr_type_t attrKey, uint32_t *num) {
	if (attrs[attrKey]) {
		int ifidx = *(uint32_t*)RTA_DATA(attrs[attrKey]);
		(*num) = ifidx;
		return 0;
	} else {
		(*num) = 0;
		return -1;
	}
}

int get_attribute_uint32_ifa(struct rtattr *attrs[IFA_MAX+1], int attrKey, uint32_t *num) {
    if (attrs[attrKey]) {
        *num = *(uint32_t*)RTA_DATA(attrs[attrKey]);
        return 0;
    }
    *num = 0;
    return -1;
}

// int get_attribute_uint32_ifa(struct rtattr *attrs[IFA_MAX+1], int attrKey, uint32_t *num) {
//     if (attrs[attrKey]) {
//         *num = *(uint32_t*)IFA_RTA(attrs[attrKey]);
//         return 0;
//     }
//     *num = 0;
//     return -1;
// }