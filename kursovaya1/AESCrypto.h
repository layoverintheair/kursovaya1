#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

class CryptoException : public std::exception {
private:
    std::string message;
public:
    explicit CryptoException(const std::string& msg);
    const char* what() const noexcept override;
};

class AESCrypto {
private:
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_KEY_HANDLE hKey;
    std::vector<BYTE> key;
    std::vector<BYTE> iv;

    void generateKeyIV();
    void cleanup();

public:
    AESCrypto(); // Генерация нового ключа и IV
    AESCrypto(const std::string& keyHex, const std::string& ivHex); // Существующие ключ и IV
    ~AESCrypto();

    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

    std::string getKeyHex() const;
    std::string getIVHex() const;

    static std::vector<BYTE> hexToBytes(const std::string& hex);
    static std::string bytesToHex(const std::vector<BYTE>& bytes);
};
