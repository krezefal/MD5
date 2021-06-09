#pragma once

/**
 * @author krezefal
 * Project on GitHub: https://github.com/krezefal/MD5
 */

#include <random>
#include <cassert>

#include "../md5/MD5.hpp"

std::string randomString();

std::vector<std::vector<std::string>> findSecondPreimages(const std::string& fullHash, const std::vector<int>& byteHashSizes,
                                                   std::vector<long>& secondPreimageComplexities) {
    for (int byteHashSize : byteHashSizes) {
        assert((byteHashSize > 0 && byteHashSize <= MD5_HASH_BIT_LENGTH) && "Incorrect hash size");
    }

    std::vector<int> hexHashSizes;
    for (int byteHashSize : byteHashSizes) hexHashSizes.push_back(byteHashSize / 4);

    std::vector<std::vector<std::string>> hashCollections(hexHashSizes.size());
    std::string someHash;
    MD5 md5;

    for (int i = 0; i < hexHashSizes.size(); i++) {
        std::string targetHash = fullHash.substr(0, hexHashSizes[i]);
        long complexity = 0;

        do {
            complexity++;
            someHash = md5.calcHash(randomString()).substr(0, hexHashSizes[i]);
            hashCollections[i].push_back(someHash);
        } while (targetHash != someHash);

        secondPreimageComplexities.push_back(complexity);
    }

    return hashCollections;
}

void findCollisions(const std::vector<int>& byteHashSizes, std::vector<long>& collisionComplexities,
                    const std::vector<std::vector<std::string>>& hashCollections) {

    for (int byteHashSize : byteHashSizes) {
        assert((byteHashSize > 0 && byteHashSize <= MD5_HASH_BIT_LENGTH) && "Incorrect hash size");
    }

    std::vector<int> hexHashSizes;
    for (int byteHashSize : byteHashSizes) hexHashSizes.push_back(byteHashSize / 4);

    for (int i = 0; i < hexHashSizes.size(); i++) {
        bool exitFlag = false;
        long complexity = 0;

        for (int j = 0; j < hashCollections[i].size(); j++) {
            for (int k = j + 1; k < hashCollections[i].size(); k++) {
                complexity++;
                if ((hashCollections[i][j] == hashCollections[i][k])) {
                    exitFlag = true;
                    break;
                }
            }
            if (exitFlag) break;
        }

        if (!exitFlag) complexity = -1;

        collisionComplexities.push_back(complexity);
    }
}



std::string randomString() {
    std::string str("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    std::random_device rd;
    std::mt19937 generator(rd());

    std::shuffle(str.begin(), str.end(), generator);

    return str.substr(0, 32);
}