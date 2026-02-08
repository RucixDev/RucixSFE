#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <cstdint>

class SHA256 {
public:
    SHA256();
    void update(const uint8_t* data, size_t len);
    void update(const std::string& data);
    std::vector<uint8_t> final();
    static std::vector<uint8_t> hash(const std::string& data);
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

private:
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t bitLen;
    uint32_t bufferLen;
    
    void transform();
};

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

std::vector<uint8_t> pbkdf2_sha256(const std::string& password, const std::vector<uint8_t>& salt, int iterations, int keyLen);

class AES256 {
public:
    AES256(const std::vector<uint8_t>& key);
    void encryptBlock(const uint8_t in[16], uint8_t out[16]);
    void decryptBlock(const uint8_t in[16], uint8_t out[16]);

private:
    uint8_t roundKeys[240];
    void keyExpansion(const std::vector<uint8_t>& key);
};

void aes256_ctr_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& data);

#endif
