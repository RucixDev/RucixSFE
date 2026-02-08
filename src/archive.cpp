#include "archive.h"
#include "crypto.h"
#include "utils.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace fs = std::filesystem;

static void pack16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(v & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
}

static void pack64(std::vector<uint8_t>& buf, uint64_t v) {
    for(int i=0; i<8; i++) buf.push_back((v >> (i*8)) & 0xFF);
}

static uint16_t unpack16(const uint8_t* buf) {
    return buf[0] | (buf[1] << 8);
}

static uint64_t unpack64(const uint8_t* buf) {
    uint64_t v = 0;
    for(int i=0; i<8; i++) v |= ((uint64_t)buf[i] << (i*8));
    return v;
}

Archive::CryptoState::CryptoState(const std::vector<uint8_t>& k, const std::vector<uint8_t>& i) 
    : key(k), iv(i), counter(i), keystream(16), keystream_pos(16) {
    if (key.size() != 32 || iv.size() != 16) throw std::runtime_error("Invalid key/iv size");
}

void Archive::CryptoState::crypt(const uint8_t* in, uint8_t* out, size_t len) {
    AES256 aes(key);
    for (size_t i = 0; i < len; i++) {
        if (keystream_pos >= 16) {
            aes.encryptBlock(counter.data(), keystream.data());
            for (int j = 15; j >= 0; j--) {
                if (++counter[j] != 0) break;
            }
            keystream_pos = 0;
        }
        out[i] = in[i] ^ keystream[keystream_pos++];
    }
}

void Archive::CryptoState::crypt(std::vector<uint8_t>& data) {
    crypt(data.data(), data.data(), data.size());
}

class ChunkedWriter {
public:
    ChunkedWriter(std::ofstream& stream, const std::vector<uint8_t>& aesKey, 
                 const std::vector<uint8_t>& iv, const std::vector<uint8_t>& macKey)
        : out(stream), aesState(aesKey, iv), macKey(macKey), sequenceNum(0) {
        buffer.reserve(CHUNK_SIZE);
    }

    ~ChunkedWriter() {
        try {
            flush();
        } catch (...) {}
    }

    void write(const uint8_t* data, size_t len) {
        size_t offset = 0;
        while (offset < len) {
            size_t space = CHUNK_SIZE - buffer.size();
            size_t toCopy = std::min(space, len - offset);
            buffer.insert(buffer.end(), data + offset, data + offset + toCopy);
            offset += toCopy;
            if (buffer.size() == CHUNK_SIZE) {
                flush();
            }
        }
    }

    void write(const std::vector<uint8_t>& data) {
        write(data.data(), data.size());
    }

    void flush() {
        if (buffer.empty()) return;

        aesState.crypt(buffer);

        std::vector<uint8_t> hmacInput;
        pack64(hmacInput, sequenceNum);
        hmacInput.insert(hmacInput.end(), buffer.begin(), buffer.end());

        std::vector<uint8_t> mac = hmac_sha256(macKey, hmacInput);

        uint16_t size = (uint16_t)buffer.size();
        out.write((char*)&size, 2);
        out.write((char*)buffer.data(), buffer.size());
        out.write((char*)mac.data(), mac.size());

        sequenceNum++;
        buffer.clear();
    }

private:
    static const size_t CHUNK_SIZE = 64 * 1024;
    std::ofstream& out;
    Archive::CryptoState aesState;
    std::vector<uint8_t> macKey;
    uint64_t sequenceNum;
    std::vector<uint8_t> buffer;
};

class ChunkedReader {
public:
    ChunkedReader(std::ifstream& stream, const std::vector<uint8_t>& aesKey, 
                 const std::vector<uint8_t>& iv, const std::vector<uint8_t>& macKey)
        : in(stream), aesState(aesKey, iv), macKey(macKey), sequenceNum(0), bufferPos(0) {}

    bool read(uint8_t* outData, size_t len) {
        size_t offset = 0;
        while (offset < len) {
            if (bufferPos >= buffer.size()) {
                if (!readChunk()) {
                    return false;
                }
            }
            size_t available = buffer.size() - bufferPos;
            size_t toCopy = std::min(available, len - offset);
            memcpy(outData + offset, buffer.data() + bufferPos, toCopy);
            bufferPos += toCopy;
            offset += toCopy;
        }
        return true;
    }

    template<typename T>
    bool readVal(T* val) {
        return read((uint8_t*)val, sizeof(T));
    }
    
    bool readVec(std::vector<uint8_t>& vec, size_t len) {
        vec.resize(len);
        return read(vec.data(), len);
    }

private:
    bool readChunk() {
        uint16_t size;
        if (!in.read((char*)&size, 2)) {
             return false;
        }
        
        std::vector<uint8_t> ciphertext(size);
        if (!in.read((char*)ciphertext.data(), size)) {
             throw std::runtime_error("Unexpected EOF in chunk");
        }

        std::vector<uint8_t> mac(32);
        if (!in.read((char*)mac.data(), 32)) {
             throw std::runtime_error("Unexpected EOF reading MAC");
        }

        std::vector<uint8_t> hmacInput;
        pack64(hmacInput, sequenceNum);
        hmacInput.insert(hmacInput.end(), ciphertext.begin(), ciphertext.end());
        
        std::vector<uint8_t> expectedMac = hmac_sha256(macKey, hmacInput);
        if (mac != expectedMac) {
            throw std::runtime_error("Integrity check failed! Data has been tampered with or wrong password.");
        }

        aesState.crypt(ciphertext);
        buffer = ciphertext;
        bufferPos = 0;
        sequenceNum++;
        return true;
    }

    std::ifstream& in;
    Archive::CryptoState aesState;
    std::vector<uint8_t> macKey;
    uint64_t sequenceNum;
    std::vector<uint8_t> buffer;
    size_t bufferPos;
};

void Archive::encrypt(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    fs::path input(inputPath);
    if (!fs::exists(input)) throw std::runtime_error("Input path does not exist");
    input = fs::absolute(input);

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot create output file");

    out.write("RUCX\x02", 5);

    std::vector<uint8_t> salt = Utils::randomBytes(32);
    std::vector<uint8_t> iv = Utils::randomBytes(16);
    out.write((char*)salt.data(), 32);
    out.write((char*)iv.data(), 16);

    std::vector<uint8_t> keys = pbkdf2_sha256(password, salt, 300000, 64);
    std::vector<uint8_t> aesKey(keys.begin(), keys.begin() + 32);
    std::vector<uint8_t> macKey(keys.begin() + 32, keys.end());

    ChunkedWriter writer(out, aesKey, iv, macKey);

    struct FileProcessor {
        ChunkedWriter& writer;
        fs::path basePath;

        FileProcessor(ChunkedWriter& w, fs::path base) : writer(w), basePath(base) {}

        void process(const fs::path& path) {
            if (fs::is_directory(path)) {
                for (const auto& entry : fs::directory_iterator(path)) {
                    process(entry.path());
                }
            } else if (fs::is_regular_file(path)) {
                std::vector<uint8_t> meta;
                meta.push_back(0x01);

                std::string relPath = fs::relative(path, basePath).generic_string();
                if (relPath == ".") relPath = path.filename().generic_string();

                if (relPath.size() > 65535) throw std::runtime_error("Path too long");
                pack16(meta, (uint16_t)relPath.size());
                for(char c : relPath) meta.push_back((uint8_t)c);
                
                uint64_t size = fs::file_size(path);
                pack64(meta, size);

                writer.write(meta);

                std::ifstream in(path, std::ios::binary);
                std::vector<uint8_t> buffer(4096);
                while (in) {
                    in.read((char*)buffer.data(), buffer.size());
                    size_t n = in.gcount();
                    if (n == 0) break;
                    writer.write((uint8_t*)buffer.data(), n);
                }
            }
        }
    };

    fs::path base = fs::is_directory(input) ? input : input.parent_path();
    FileProcessor processor(writer, base);
    processor.process(input);

    std::vector<uint8_t> endMarker = {0x00};
    writer.write(endMarker);
    writer.flush();
}

void Archive::decrypt(const std::string& inputPath, const std::string& outputDir, const std::string& password) {
    std::ifstream in(inputPath, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file");

    char header[5];
    in.read(header, 5);
    if (memcmp(header, "RUCX\x02", 5) != 0) throw std::runtime_error("Invalid file format or version (expected v2)");

    std::vector<uint8_t> salt(32);
    std::vector<uint8_t> iv(16);
    in.read((char*)salt.data(), 32);
    in.read((char*)iv.data(), 16);

    std::vector<uint8_t> keys = pbkdf2_sha256(password, salt, 300000, 64);
    std::vector<uint8_t> aesKey(keys.begin(), keys.begin() + 32);
    std::vector<uint8_t> macKey(keys.begin() + 32, keys.end());

    ChunkedReader reader(in, aesKey, iv, macKey);

    fs::path outRoot(outputDir);
    if (!fs::exists(outRoot)) fs::create_directories(outRoot);

    while (true) {
        uint8_t type;
        if (!reader.readVal(&type)) {
             break;
        }

        if (type == 0x00) break; 
        if (type == 0x01) {
            uint8_t lenBuf[2];
            if (!reader.read(lenBuf, 2)) throw std::runtime_error("Truncated archive");
            uint16_t pathLen = unpack16(lenBuf);

            std::vector<uint8_t> pathBuf;
            if (!reader.readVec(pathBuf, pathLen)) throw std::runtime_error("Truncated archive");
            std::string pathStr(pathBuf.begin(), pathBuf.end());

            uint8_t sizeBuf[8];
            if (!reader.read(sizeBuf, 8)) throw std::runtime_error("Truncated archive");
            uint64_t fileSize = unpack64(sizeBuf);

            fs::path filePath = outRoot / pathStr;
            fs::create_directories(filePath.parent_path());
            std::ofstream outFile(filePath, std::ios::binary);
            
            std::vector<uint8_t> buffer(4096);
            uint64_t remaining = fileSize;
            while (remaining > 0) {
                size_t toRead = std::min((uint64_t)buffer.size(), remaining);
                if (!reader.read(buffer.data(), toRead)) throw std::runtime_error("Unexpected EOF in file content");
                outFile.write((char*)buffer.data(), toRead);
                remaining -= toRead;
            }
            std::cout << "Decrypted: " << pathStr << std::endl;
        } else {
            throw std::runtime_error("Corrupt archive: Unknown entry type");
        }
    }
}
