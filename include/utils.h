#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <cstdint>

class Utils {
public:
    static std::vector<uint8_t> randomBytes(size_t len);
};

#endif 
