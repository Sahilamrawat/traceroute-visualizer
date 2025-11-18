#pragma once
#include <string>
#include <vector>

struct DNSRecord {
    std::string type;
    std::string value;
};

std::vector<DNSRecord> dns_lookup_full(const std::string& host, int dns_type);
