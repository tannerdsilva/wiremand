#include "Crtnetlink.h"

/*
 * Crtnetlink: a minimal, correct netlink/rtnetlink dump helper.
 *
 * The original implementation was hasty and had several correctness bugs:
 *   - The request structs (nlmsghdr + rtmsg / ifaddrmsg / ifinfomsg) were
 *     never zero-initialized, so garbage bytes in rtm_dst_len / rtm_table /
 *     rtm_src_len acted as kernel-side filters. In particular the IPv4
 *     default route (0.0.0.0/0, dst_len 0) was silently dropped, so
 *     `RTNetlink.getRoutesV4()` reported no default route even when one
 *     existed. The kernel's route dump (inet_dump_fib) filters on those
 *     fields, so the request MUST be fully zeroed before use.
 *   - do_address_dump_request_v6 was missing a semicolon (struct rtmsg rtm),
 *     which clang only tolerates as a warning.
 *   - The dump-response readers used fixed 64KB stack buffers and duplicated
 *     the message loop three times. Multi-packet dumps on systems with many
 *     routes/interfaces could truncate.
 *   - struct sockaddr_nl was read uninitialized in the response readers.
 *   - send() results were not validated for short sends / EINTR.
 *
 * This pass consolidates the dump machinery, uses a dynamically-sized receive
 * buffer, zero-initializes every request, and validates all syscalls. The
 * public C surface is unchanged so the Swift consumer (RTNetlink.swift)
 * compiles unmodified. Apple Blocks are used for the handler callbacks (they
 * bridge to Swift closures); the target must be compiled with -fblocks.
 */

/* ------------------------------------------------------------------ */
/*  Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= (unsigned short)max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }
}

static int rtnl_recvmsg(int fd, struct sockaddr_nl *peer, char **answer, ssize_t *len_out)
{
    /* Two-phase receive: first PEEK to size the buffer, then a real read.
     * Returns 0 on success, -errno on failure. */
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = peer,
        .msg_namelen = sizeof(*peer),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char *buf = NULL;
    ssize_t len;

    for (;;) {
        iov.iov_base = NULL;
        iov.iov_len = 0;
        len = recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC);
        if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if (len < 0) {
            return -errno;
        }
        break;
    }

    if (len == 0) {
        return -ENODATA;
    }

    buf = malloc((size_t)len);
    if (buf == NULL) {
        return -ENOMEM;
    }

    for (;;) {
        iov.iov_base = buf;
        iov.iov_len = (size_t)len;
        len = recvmsg(fd, &msg, 0);
        if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if (len < 0) {
            free(buf);
            return -errno;
        }
        break;
    }

    *answer = buf;
    *len_out = len;
    return 0;
}

/* Common dump response walker. Iterates every netlink message in the stream,
 * invoking `handler` for each non-error, non-DONE message. Returns 0 on a
 * clean NLMSG_DONE terminator, or a negative errno-coded error.
 *
 * Only messages from the kernel (nl_pid == 0) are considered. */
static int dump_walk(int sock, void (^handler)(struct nlmsghdr *))
{
    for (;;) {
        struct sockaddr_nl nladdr;
        char *buf = NULL;
        ssize_t len = 0;
        int rc = rtnl_recvmsg(sock, &nladdr, &buf, &len);
        if (rc < 0) {
            return rc;
        }

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        int msglen = (int)len;

        while (NLMSG_OK(h, msglen)) {
            if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
                free(buf);
                return -EINTR;
            }
            if (nladdr.nl_pid != 0) {
                /* Not from the kernel; skip. */
                h = NLMSG_NEXT(h, msglen);
                continue;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                free(buf);
                return -EIO;
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                free(buf);
                return 0;
            }
            handler(h);
            h = NLMSG_NEXT(h, msglen);
        }
        free(buf);
        /* End of this packet; loop to read the next one. */
    }
}

/* Build and send a zero-initialized RTM_* dump request. The `family` is the
 * address family to dump; `msg_type` is RTM_GETROUTE / RTM_GETADDR /
 * RTM_GETLINK. Zeroing the entire request is essential: the kernel reads
 * rtm_dst_len / rtm_table / rtm_src_len as dump filters, and garbage here
 * silently hides routes. Returns 0 on success, -errno on failure. */
static int send_dump_request(int sock, int msg_type, unsigned char family)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_type = msg_type;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.nlh.nlmsg_len = sizeof(request);
    request.nlh.nlmsg_seq = (unsigned int)time(NULL);
    request.rtm.rtm_family = family;

    ssize_t sent;
    do {
        sent = send(sock, &request, sizeof(request), 0);
    } while (sent < 0 && (errno == EINTR || errno == EAGAIN));

    if (sent < 0) {
        return -errno;
    }
    if (sent != (ssize_t)sizeof(request)) {
        return -EIO; /* short send */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Socket lifecycle                                                   */
/* ------------------------------------------------------------------ */

int open_netlink(void)
{
    struct sockaddr_nl saddr;
    int sock;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
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

/* ------------------------------------------------------------------ */
/*  Interfaces                                                         */
/* ------------------------------------------------------------------ */

int do_interface_dump_request(int sock)
{
    return send_dump_request(sock, RTM_GETLINK, AF_UNSPEC);
}

int get_interface_dump_response(int sock, void (^hndlr)(struct nlmsghdr *))
{
    return dump_walk(sock, hndlr);
}

int read_interface(struct nlmsghdr *nl_header_answer, void (^hndlr)(struct ifinfomsg *ifin, struct rtattr *attrs[IFLA_MAX + 1]))
{
    if (nl_header_answer->nlmsg_type != RTM_NEWLINK) {
        return -1;
    }

    struct ifinfomsg *ifin = NLMSG_DATA(nl_header_answer);
    int len = (int)nl_header_answer->nlmsg_len;
    struct rtattr *tb[IFLA_MAX + 1];

    len -= (int)NLMSG_LENGTH(sizeof(*ifin));
    if (len < 0) {
        return -1;
    }

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifin), len);
    hndlr(ifin, tb);
    return 0;
}

void get_attribute_data_ifla(struct rtattr *attrs[IFLA_MAX + 1], int attrKey, char **buf)
{
    if (attrs[attrKey] && RTA_PAYLOAD(attrs[attrKey]) >= 6) {
        unsigned char *d = (unsigned char *)RTA_DATA(attrs[attrKey]);
        *buf = malloc(32);
        if (*buf == NULL) {
            return;
        }
        snprintf(*buf, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
                 d[0], d[1], d[2], d[3], d[4], d[5]);
    } else {
        *buf = NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  Addresses                                                          */
/* ------------------------------------------------------------------ */

int do_address_dump_request_v4(int sock)
{
    return send_dump_request(sock, RTM_GETADDR, AF_INET);
}

int do_address_dump_request_v6(int sock)
{
    return send_dump_request(sock, RTM_GETADDR, AF_INET6);
}

int get_address_dump_response(int sock, void (^hndlr)(struct nlmsghdr *))
{
    return dump_walk(sock, hndlr);
}

int read_address(struct nlmsghdr *nl_header_answer, void (^hndlr)(struct ifaddrmsg *ifa, struct rtattr *attrs[IFA_MAX + 1]))
{
    struct ifaddrmsg *ifa = NLMSG_DATA(nl_header_answer);
    int len = (int)nl_header_answer->nlmsg_len;
    struct rtattr *tb[IFA_MAX + 1];

    len -= (int)NLMSG_LENGTH(sizeof(*ifa));
    if (len < 0) {
        return -1;
    }

    parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);
    hndlr(ifa, tb);
    return 0;
}

void get_attribute_data_ifa(unsigned char family, struct rtattr *attrs[IFA_MAX + 1], int attrKey, char **buf)
{
    if (attrs[attrKey]) {
        *buf = malloc(256);
        if (*buf == NULL) {
            return;
        }
        if (inet_ntop(family, RTA_DATA(attrs[attrKey]), *buf, 256) == NULL) {
            free(*buf);
            *buf = NULL;
        }
    } else {
        *buf = NULL;
    }
}

int get_attribute_uint32_ifa(struct rtattr *attrs[IFA_MAX + 1], int attrKey, uint32_t *num)
{
    if (attrs[attrKey] && RTA_PAYLOAD(attrs[attrKey]) >= sizeof(uint32_t)) {
        *num = *(const uint32_t *)RTA_DATA(attrs[attrKey]);
        return 0;
    }
    *num = 0;
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Routes                                                             */
/* ------------------------------------------------------------------ */

int do_route_dump_request_v4(int sock)
{
    return send_dump_request(sock, RTM_GETROUTE, AF_INET);
}

int do_route_dump_request_v6(int sock)
{
    return send_dump_request(sock, RTM_GETROUTE, AF_INET6);
}

int get_route_dump_response(int sock, void (^hndlr)(struct nlmsghdr *))
{
    return dump_walk(sock, hndlr);
}

int read_route(struct nlmsghdr *nl_header_answer, void (^hndlr)(struct rtmsg *r, struct rtattr *tb[RTA_MAX + 1]))
{
    struct rtmsg *r = NLMSG_DATA(nl_header_answer);
    int len = (int)nl_header_answer->nlmsg_len;
    struct rtattr *tb[RTA_MAX + 1];

    len -= (int)NLMSG_LENGTH(sizeof(*r));
    if (len < 0) {
        return -1;
    }

    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
    hndlr(r, tb);
    return 0;
}

void get_attribute_data_rt(unsigned char family, struct rtattr *attrs[RTA_MAX + 1], enum rtattr_type_t attrKey, char **buf)
{
    if (attrs[attrKey]) {
        *buf = malloc(256);
        if (*buf == NULL) {
            return;
        }
        if (inet_ntop(family, RTA_DATA(attrs[attrKey]), *buf, 256) == NULL) {
            free(*buf);
            *buf = NULL;
        }
    } else {
        *buf = NULL;
    }
}

int get_attribute_uint32_rt(struct rtattr *attrs[RTA_MAX + 1], enum rtattr_type_t attrKey, uint32_t *num)
{
    if (attrs[attrKey] && RTA_PAYLOAD(attrs[attrKey]) >= sizeof(uint32_t)) {
        *num = *(const uint32_t *)RTA_DATA(attrs[attrKey]);
        return 0;
    }
    *num = 0;
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Ambient capability raising                                         */
/*                                                                      *
 * The daemon needs CAP_NET_ADMIN in its ambient set so that child      *
 * processes (wg, ip, etc.) spawned via posix_spawn inherit the         *
 * capability. Systemd's AmbientCapabilities= directive should set      *
 * this, but on some configurations it does not take effect. This       *
 * fallback raises it from the process's own Permitted+Inheritable      *
 * sets, which are already granted by the systemd unit or file cap.     */
/* ------------------------------------------------------------------ */

int raise_ambient_cap_net_admin(void)
{
    int rc = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, CAP_NET_ADMIN, 0);
    if (rc < 0) {
        return -errno;
    }
    return 0;
}