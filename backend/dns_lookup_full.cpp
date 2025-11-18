#include "dns_lookup_full.hpp"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string>
#include <vector>

static std::vector<DNSRecord> parse_dns(u_char* answer, int len) {
    std::vector<DNSRecord> results;

    ns_msg msg;
    if (ns_initparse(answer, len, &msg) < 0)
        return results;

    int count = ns_msg_count(msg, ns_s_an);

    for (int i = 0; i < count; i++) {
        ns_rr rr;
        ns_parserr(&msg, ns_s_an, i, &rr);

        std::string type, value;

        switch (ns_rr_type(rr)) {
        case ns_t_a: {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof(ip));
            type = "A";
            value = ip;
            break;
        }
        case ns_t_aaaa: {
            char ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ns_rr_rdata(rr), ip6, sizeof(ip6));
            type = "AAAA";
            value = ip6;
            break;
        }
        case ns_t_cname: {
            char cname[1024];
            ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                               ns_rr_rdata(rr), cname, sizeof(cname));
            type = "CNAME";
            value = cname;
            break;
        }
        case ns_t_ns: {
            char nsd[1024];
            ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                               ns_rr_rdata(rr), nsd, sizeof(nsd));
            type = "NS";
            value = nsd;
            break;
        }
        case ns_t_mx: {
            const u_char* rdata = ns_rr_rdata(rr);
            char exch[1024];
            ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                               rdata + 2, exch, sizeof(exch));
            type = "MX";
            value = exch;
            break;
        }
        case ns_t_txt: {
            int size = ns_rr_rdata(rr)[0];
            value = std::string((char*)ns_rr_rdata(rr) + 1, size);
            type = "TXT";
            break;
        }
        }

        if (!value.empty())
            results.push_back({type, value});
    }

    return results;
}

std::vector<DNSRecord> dns_lookup_full(const std::string& host, int dns_type) {
    u_char answer[4096];
    int len = res_query(host.c_str(), ns_c_in, dns_type, answer, sizeof(answer));
    if (len < 0)
        return {};
    return parse_dns(answer, len);
}
