#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <string>
#include <vector>
#include <filesystem>

class Archive {
public:
    static void encrypt(const std::string& inputPath, const std::string& outputPath, const std::string& password);
    static void decrypt(const std::string& inputPath, const std::string& outputDir, const std::string& password);

    struct CryptoState {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        std::vector<uint8_t> keystream;
        size_t keystream_pos;
        
        CryptoState(const std::vector<uint8_t>& k, const std::vector<uint8_t>& i);
        void crypt(const uint8_t* in, uint8_t* out, size_t len);
        void crypt(std::vector<uint8_t>& data);
    };

private:
};

#endif
