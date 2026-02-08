#include "utils.h"
#include <random>
#include <algorithm>

std::vector<uint8_t> Utils::randomBytes(size_t len) {
    std::vector<uint8_t> bytes(len);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < len; i++) {
        bytes[i] = static_cast<uint8_t>(dis(gen));
    }
    return bytes;
}
