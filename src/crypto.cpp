#include "crypto.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <iostream>

namespace {
    constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    
    inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }
    
    inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & (b | c)) | (b & c);
    }
    
    inline uint32_t sig0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    inline uint32_t sig1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
    inline uint32_t Sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    inline uint32_t Sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    void pack32(uint8_t* str, uint32_t x) {
        str[0] = (uint8_t)(x >> 24);
        str[1] = (uint8_t)(x >> 16);
        str[2] = (uint8_t)(x >> 8);
        str[3] = (uint8_t)(x);
    }
}

SHA256::SHA256() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    bitLen = 0;
    bufferLen = 0;
}

void SHA256::update(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[bufferLen++] = data[i];
        if (bufferLen == 64) {
            transform();
            bufferLen = 0;
        }
    }
    bitLen += len * 8;
}

void SHA256::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
}

void SHA256::transform() {
    uint32_t m[64];
    for (int i = 0; i < 16; i++) {
        m[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + Sig1(e) + choose(e, f, g) + K[i] + m[i];
        uint32_t t2 = Sig0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

std::vector<uint8_t> SHA256::final() {
    uint8_t i = 0;
    buffer[bufferLen++] = 0x80;
    if (bufferLen > 56) {
        while (bufferLen < 64) buffer[bufferLen++] = 0;
        transform();
        bufferLen = 0;
    }
    while (bufferLen < 56) buffer[bufferLen++] = 0;
    
    uint64_t len = bitLen;
    for (int i = 0; i < 8; i++) {
        buffer[63 - i] = (uint8_t)(len & 0xFF);
        len >>= 8;
    }
    transform();

    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 8; i++) {
        pack32(&hash[i * 4], state[i]);
    }
    return hash;
}

std::vector<uint8_t> SHA256::hash(const std::string& data) {
    SHA256 ctx;
    ctx.update(data);
    return ctx.final();
}

std::vector<uint8_t> SHA256::hash(const std::vector<uint8_t>& data) {
    SHA256 ctx;
    ctx.update(data.data(), data.size());
    return ctx.final();
}

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> k = key;
    if (k.size() > 64) {
        k = SHA256::hash(k);
    }
    if (k.size() < 64) {
        k.resize(64, 0);
    }

    std::vector<uint8_t> i_pad(64), o_pad(64);
    for (int i = 0; i < 64; i++) {
        i_pad[i] = k[i] ^ 0x36;
        o_pad[i] = k[i] ^ 0x5C;
    }

    SHA256 inner;
    inner.update(i_pad.data(), 64);
    inner.update(data.data(), data.size());
    std::vector<uint8_t> inner_hash = inner.final();

    SHA256 outer;
    outer.update(o_pad.data(), 64);
    outer.update(inner_hash.data(), 32);
    return outer.final();
}

std::vector<uint8_t> pbkdf2_sha256(const std::string& password, const std::vector<uint8_t>& salt, int iterations, int keyLen) {
    std::vector<uint8_t> key;
    std::vector<uint8_t> passBytes(password.begin(), password.end());
    int blocks = (keyLen + 31) / 32;
    
    for (int i = 1; i <= blocks; i++) {
        std::vector<uint8_t> salt_i = salt;
        salt_i.push_back((i >> 24) & 0xFF);
        salt_i.push_back((i >> 16) & 0xFF);
        salt_i.push_back((i >> 8) & 0xFF);
        salt_i.push_back(i & 0xFF);

        std::vector<uint8_t> U = hmac_sha256(passBytes, salt_i);
        std::vector<uint8_t> T = U;

        for (int j = 1; j < iterations; j++) {
            U = hmac_sha256(passBytes, U);
            for (size_t k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        for (size_t k = 0; k < 32 && key.size() < (size_t)keyLen; k++) {
            key.push_back(T[k]);
        }
    }
    return key;
}

namespace {
    const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    
    const uint8_t Rcon[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
    };

    void SubBytes(uint8_t state[16]) {
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
    }

    void ShiftRows(uint8_t state[16]) {
        uint8_t tmp[16];
        tmp[0] = state[0]; tmp[1] = state[5]; tmp[2] = state[10]; tmp[3] = state[15];
        tmp[4] = state[4]; tmp[5] = state[9]; tmp[6] = state[14]; tmp[7] = state[3];
        tmp[8] = state[8]; tmp[9] = state[13]; tmp[10] = state[2]; tmp[11] = state[7];
        tmp[12] = state[12]; tmp[13] = state[1]; tmp[14] = state[6]; tmp[15] = state[11];
        memcpy(state, tmp, 16);
    }

    uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            uint8_t hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    void MixColumns(uint8_t state[16]) {
        uint8_t tmp[16];
        for (int i = 0; i < 4; i++) {
            tmp[i * 4]     = gmul(0x02, state[i * 4]) ^ gmul(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
            tmp[i * 4 + 1] = state[i * 4] ^ gmul(0x02, state[i * 4 + 1]) ^ gmul(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
            tmp[i * 4 + 2] = state[i * 4] ^ state[i * 4 + 1] ^ gmul(0x02, state[i * 4 + 2]) ^ gmul(0x03, state[i * 4 + 3]);
            tmp[i * 4 + 3] = gmul(0x03, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gmul(0x02, state[i * 4 + 3]);
        }
        memcpy(state, tmp, 16);
    }

    void AddRoundKey(uint8_t state[16], const uint8_t* key) {
        for (int i = 0; i < 16; i++) state[i] ^= key[i];
    }
}

AES256::AES256(const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::invalid_argument("AES-256 requires 32-byte key");
    keyExpansion(key);
}

void AES256::keyExpansion(const std::vector<uint8_t>& key) {
    memcpy(roundKeys, key.data(), 32);
    uint8_t temp[4];
    int i = 32;
    int rconIter = 1;
    while (i < 240) {
        memcpy(temp, &roundKeys[i - 4], 4);
        if (i % 32 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
            temp[0] ^= Rcon[rconIter++];
        } else if (i % 32 == 16) {
            for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
        }
        for (int j = 0; j < 4; j++) {
            roundKeys[i] = roundKeys[i - 32] ^ temp[j];
            i++;
        }
    }
}

void AES256::encryptBlock(const uint8_t in[16], uint8_t out[16]) {
    memcpy(out, in, 16);
    AddRoundKey(out, roundKeys);
    for (int i = 1; i < 14; i++) {
        SubBytes(out);
        ShiftRows(out);
        MixColumns(out);
        AddRoundKey(out, roundKeys + i * 16);
    }
    SubBytes(out);
    ShiftRows(out);
    AddRoundKey(out, roundKeys + 14 * 16);
}

void AES256::decryptBlock(const uint8_t in[16], uint8_t out[16]) {
    throw std::runtime_error("Not implemented");
}

void aes256_ctr_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& data) {
    AES256 aes(key);
    uint8_t counter[16];
    if (iv.size() != 16) throw std::invalid_argument("IV must be 16 bytes");
    memcpy(counter, iv.data(), 16);
    
    uint8_t keystream[16];
    size_t offset = 0;
    
    while (offset < data.size()) {
        aes.encryptBlock(counter, keystream);
        
        for (int i = 15; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
        
        size_t blockLen = std::min((size_t)16, data.size() - offset);
        for (size_t i = 0; i < blockLen; i++) {
            data[offset + i] ^= keystream[i];
        }
        offset += blockLen;
    }
}
