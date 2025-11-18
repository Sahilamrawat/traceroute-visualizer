#include <iostream>
#include <vector>
#include <string>
#include <arpa/nameser.h>

#include "dns_lookup_basic.hpp"
#include "dns_lookup_full.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: dns_tool <hostname>\n";
        return 1;
    }

    std::string host = argv[1];
    std::vector<DNSRecord> all;

    for (auto r : dns_lookup_basic(host))
        all.push_back({r.type, r.value});

    for (auto r : dns_lookup_full(host, ns_t_cname)) all.push_back(r);
    for (auto r : dns_lookup_full(host, ns_t_mx))    all.push_back(r);
    for (auto r : dns_lookup_full(host, ns_t_ns))    all.push_back(r);
    for (auto r : dns_lookup_full(host, ns_t_txt))   all.push_back(r);

    std::cout << "[\n";
    for (size_t i = 0; i < all.size(); i++) {
        std::cout << "  {\"type\": \"" << all[i].type
                  << "\", \"value\": \"" << all[i].value << "\"}";
        if (i + 1 < all.size()) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "]\n";

    return 0;
}
