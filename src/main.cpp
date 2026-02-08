#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include "archive.h"

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

std::string getPassword(const std::string& prompt) {
    std::cout << prompt;
    std::string password;
    
#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != 13) { 
        if (ch == 8) { 
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else {
            password += ch;
            std::cout << "*";
        }
    }
    std::cout << std::endl;
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    return password;
}

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " <command> [options]\n"
              << "Commands:\n"
              << "  encrypt    Encrypt a file or directory\n"
              << "  decrypt    Decrypt an archive\n"
              << "Options:\n"
              << "  -i <path>  Input path (file or folder)\n"
              << "  -o <path>  Output path (file for encrypt, folder for decrypt)\n"
              << "  -p <pass>  Password (optional)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    std::string inputPath, outputPath, password;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            inputPath = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            password = argv[++i];
        }
    }

    if (inputPath.empty() || outputPath.empty()) {
        std::cerr << "Error: Input and Output paths are required.\n";
        printUsage(argv[0]);
        return 1;
    }

    if (password.empty()) {
        password = getPassword("Enter Password: ");
    }

    try {
        if (command == "encrypt") {
            std::cout << "Encrypting " << inputPath << " to " << outputPath << "...\n";
            Archive::encrypt(inputPath, outputPath, password);
            std::cout << "Encryption successful.\n";
        } else if (command == "decrypt") {
            std::cout << "Decrypting " << inputPath << " to " << outputPath << "...\n";
            Archive::decrypt(inputPath, outputPath, password);
            std::cout << "Decryption successful.\n";
        } else {
            std::cerr << "Unknown command: " << command << "\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
