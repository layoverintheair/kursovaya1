#include "AESCrypto.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

CryptoException::CryptoException(const std::string& msg) : message(msg) {}
const char* CryptoException::what() const noexcept {
    return message.c_str();
}

AESCrypto::AESCrypto() : hAlgorithm(nullptr), hKey(nullptr) {
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        throw CryptoException("Ошибка открытия алгоритма");
    }

    LPCWSTR mode = BCRYPT_CHAIN_MODE_CBC;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<LPWSTR>(mode)),
        static_cast<ULONG>((wcslen(mode) + 1) * sizeof(WCHAR)), 0))) {
        cleanup();
        throw CryptoException("Ошибка установки режима CBC");
    }

    generateKeyIV();
}

AESCrypto::AESCrypto(const std::string& keyHex, const std::string& ivHex)
    : hAlgorithm(nullptr), hKey(nullptr) {
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        throw CryptoException("Ошибка открытия алгоритма");
    }

    LPCWSTR mode = BCRYPT_CHAIN_MODE_CBC;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<LPWSTR>(mode)),
        static_cast<ULONG>((wcslen(mode) + 1) * sizeof(WCHAR)), 0))) {
        cleanup();
        throw CryptoException("Ошибка установки режима CBC");
    }

    key = hexToBytes(keyHex);
    iv = hexToBytes(ivHex);

    if (key.size() != 32 || iv.size() != 16) {
        cleanup();
        throw CryptoException("Неверный размер ключа или IV");
    }

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0,
        key.data(), static_cast<ULONG>(key.size()), 0))) {
        cleanup();
        throw CryptoException("Ошибка создания ключа");
    }
}

AESCrypto::~AESCrypto() {
    cleanup();
}

void AESCrypto::generateKeyIV() {
    key.resize(32);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        throw CryptoException("Ошибка генерации ключа");
    }

    iv.resize(16);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, iv.data(), static_cast<ULONG>(iv.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        throw CryptoException("Ошибка генерации IV");
    }

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0,
        key.data(), static_cast<ULONG>(key.size()), 0))) {
        throw CryptoException("Ошибка создания ключа");
    }
}

void AESCrypto::cleanup() {
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    hKey = nullptr;
    hAlgorithm = nullptr;
}

std::string AESCrypto::encrypt(const std::string& plaintext) {
    if (plaintext.empty()) return "";

    size_t padLen = 16 - (plaintext.size() % 16);
    std::vector<BYTE> plaintextData(plaintext.begin(), plaintext.end());
    plaintextData.insert(plaintextData.end(), padLen, static_cast<BYTE>(padLen));

    ULONG ciphertextSize = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, plaintextData.data(),
        static_cast<ULONG>(plaintextData.size()), nullptr,
        iv.data(), static_cast<ULONG>(iv.size()), nullptr, 0,
        &ciphertextSize, 0))) {
        throw CryptoException("Ошибка получения размера при шифровании");
    }

    std::vector<BYTE> ciphertext(ciphertextSize);
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, plaintextData.data(),
        static_cast<ULONG>(plaintextData.size()), nullptr,
        iv.data(), static_cast<ULONG>(iv.size()), ciphertext.data(),
        static_cast<ULONG>(ciphertext.size()), &ciphertextSize, 0))) {
        throw CryptoException("Ошибка шифрования");
    }

    ciphertext.resize(ciphertextSize);
    return std::string(ciphertext.begin(), ciphertext.end());
}

std::string AESCrypto::decrypt(const std::string& ciphertext) {
    if (ciphertext.empty()) return "";

    std::vector<BYTE> ciphertextData(ciphertext.begin(), ciphertext.end());
    ULONG plaintextSize = 0;

    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, ciphertextData.data(),
        static_cast<ULONG>(ciphertextData.size()), nullptr,
        iv.data(), static_cast<ULONG>(iv.size()), nullptr, 0,
        &plaintextSize, 0))) {
        throw CryptoException("Ошибка получения размера при дешифровании");
    }

    std::vector<BYTE> plaintext(plaintextSize);
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, ciphertextData.data(),
        static_cast<ULONG>(ciphertextData.size()), nullptr,
        iv.data(), static_cast<ULONG>(iv.size()), plaintext.data(),
        static_cast<ULONG>(plaintext.size()), &plaintextSize, 0))) {
        throw CryptoException("Ошибка дешифрования");
    }

    if (!plaintext.empty() && plaintextSize > 0) {
        BYTE padLen = plaintext[plaintextSize - 1];
        if (padLen <= 16) {
            plaintextSize -= padLen;
        }
    }

    return std::string(plaintext.begin(), plaintext.begin() + plaintextSize);
}

std::string AESCrypto::getKeyHex() const {
    return bytesToHex(key);
}

std::string AESCrypto::getIVHex() const {
    return bytesToHex(iv);
}

std::vector<BYTE> AESCrypto::hexToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) throw CryptoException("Неверная длина hex строки");
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char* end = nullptr;
        unsigned long byte = strtoul(byteString.c_str(), &end, 16);
        if (*end != '\0' || byte > 255) throw CryptoException("Неверный hex формат");
        bytes.push_back(static_cast<BYTE>(byte));
    }
    return bytes;
}

std::string AESCrypto::bytesToHex(const std::vector<BYTE>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (BYTE byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}
