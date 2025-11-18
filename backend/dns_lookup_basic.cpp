#include "dns_lookup_basic.hpp"
#include <netdb.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

std::vector<Record> dns_lookup_basic(const std::string& host) {
    std::vector<Record> results;

    addrinfo hints{}, *res, *p;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return results;

    char ipstr[INET6_ADDRSTRLEN];

    for (p = res; p != nullptr; p = p->ai_next) {
        void* addr;
        std::string type;

        if (p->ai_family == AF_INET) {
            sockaddr_in* ipv4 = (sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            type = "A";
        } else {
            sockaddr_in6* ipv6 = (sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            type = "AAAA";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        results.push_back(Record{type, std::string(ipstr)});
    }

    freeaddrinfo(res);
    return results;
}
