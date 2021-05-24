/**
 * @author krezefal
 * Project on GitHub: https://github.com/krezefal/MD5
 */

#include <iostream>

#include "../md5/MD5.hpp"

int main() {

    std::string message;
    std::cout << "Input message to hashing: ";
    std::cin >> message;

    MD5 md5;
    std::cout << "MD5 hash: ";
    std::cout << md5.calcHash(message);

    return 0;
}
