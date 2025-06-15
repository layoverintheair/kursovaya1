#include "AESCrypto.h"
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

void printMenu() {
    std::cout << "\nМеню:\n";
    std::cout << "1. Зашифровать текст\n";
    std::cout << "2. Расшифровать текст\n";
    std::cout << "3. Показать текущий ключ и IV\n";
    std::cout << "4. Использовать существующий ключ и IV\n";
    std::cout << "5. Выход\n";
    std::cout << "Выберите действие: ";
}

int main() {
    try {
        SetConsoleCP(1251);
        SetConsoleOutputCP(1251);

        AESCrypto crypto;
        int choice;

        do {
            printMenu();
            std::cin >> choice;
            std::cin.ignore();

            switch (choice) {
            case 1: {
                std::string plaintext;
                std::cout << "Введите текст для шифрования: ";
                std::getline(std::cin, plaintext);

                try {
                    std::string ciphertext = crypto.encrypt(plaintext);
                    std::cout << "Зашифрованный текст (hex): "
                        << AESCrypto::bytesToHex(std::vector<BYTE>(ciphertext.begin(), ciphertext.end()))
                        << std::endl;
                    std::cout << "Ключ: " << crypto.getKeyHex() << std::endl;
                    std::cout << "IV: " << crypto.getIVHex() << std::endl;
                }
                catch (const CryptoException& e) {
                    std::cerr << "Ошибка шифрования: " << e.what() << std::endl;
                }
                break;
            }

            case 2: {
                std::string ciphertextHex;
                std::cout << "Введите зашифрованный текст (hex): ";
                std::getline(std::cin, ciphertextHex);

                try {
                    std::vector<BYTE> ciphertext = AESCrypto::hexToBytes(ciphertextHex);
                    std::string plaintext = crypto.decrypt(std::string(ciphertext.begin(), ciphertext.end()));
                    std::cout << "Расшифрованный текст: " << plaintext << std::endl;
                }
                catch (const CryptoException& e) {
                    std::cerr << "Ошибка дешифрования: " << e.what() << std::endl;
                }
                break;
            }

            case 3:
                std::cout << "Ключ (hex): " << crypto.getKeyHex() << std::endl;
                std::cout << "IV (hex): " << crypto.getIVHex() << std::endl;
                break;

            case 4: {
                std::string keyHex, ivHex;
                std::cout << "Введите ключ (hex, 64 символа): ";
                std::getline(std::cin, keyHex);
                std::cout << "Введите IV (hex, 32 символа): ";
                std::getline(std::cin, ivHex);

                try {
                    crypto = AESCrypto(keyHex, ivHex);
                    std::cout << "Ключ и IV установлены успешно." << std::endl;
                }
                catch (const CryptoException& e) {
                    std::cerr << "Ошибка установки ключа/IV: " << e.what() << std::endl;
                }
                break;
            }

            case 5:
                std::cout << "Выход из программы." << std::endl;
                break;

            default:
                std::cout << "Неверный выбор. Попробуйте снова." << std::endl;
            }

        } while (choice != 5);

    }
    catch (const std::exception& e) {
        std::cerr << "Фатальная ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
