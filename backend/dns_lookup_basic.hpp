#pragma once
#include <string>
#include <vector>

struct Record {
    std::string type;
    std::string value;
};

std::vector<Record> dns_lookup_basic(const std::string& host);
