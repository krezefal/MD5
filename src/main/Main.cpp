/**
 * @author krezefal
 * Project on GitHub: https://github.com/krezefal/MD5
 */

#include <iostream>
#include <fstream>

#include "../md5/MD5.hpp"
#include "../tests/Tests.hpp"

int main() {

    std::cout << std::endl;

    std::string message;
    std::cout << "Input message to hashing: ";
    getline(std::cin, message);

    MD5 md5;
    std::cout << "MD5 hash: ";
    std::cout << md5.calcHash(message);

    std::cout << std::endl;

    std::string decision;
    std::cout << std::endl << "Perform MD5 hash testing? (finding second preimage and collision complexities) [y/n]: ";
    getline(std::cin, decision);

    if (decision == "y") {

        std::cout << "Input message to find the second preimage and compose hashes' collection to find the collision: ";
        getline(std::cin, message);

        std::vector<int> byteHashSizes { 8, 12, 16, 20, 24 };
        std::vector<long> secondPreimageComplexities;
        std::vector<std::vector<std::string>> hashCollections = findSecondPreimages(md5.calcHash(message),
                                                                                     byteHashSizes, secondPreimageComplexities);
        std::cout << std::endl;

        std::cout << "Second preimage complexity: " << std::endl;
        for (int i = 0; i < byteHashSizes.size(); i++) {
            std::cout << "    For hash size = " << byteHashSizes[i] << " bit = " << secondPreimageComplexities[i] << std::endl;
        }

        std::cout << std::endl;

        std::vector<long> collisionComplexities;
        findCollisions(byteHashSizes, collisionComplexities, hashCollections);

        std::cout << "Collision complexity: " << std::endl;
        for (int i = 0; i < byteHashSizes.size(); i++) {
            std::cout << "    For hash size = " << byteHashSizes[i] << " bit = ";
            (collisionComplexities[i] == -1) ? std::cout << "collision not found" : std::cout << collisionComplexities[i];
            std::cout << std::endl;
        }
    }

    std::cout << std::endl << "Calculate average second preimage and collisions complexities? (Test will perform 1000 iteration (~12h)) [y/n]: ";
    std::cin >> decision;

    if (decision == "y") {

        std::vector<int> hashSizes { 8, 12, 16, 20, 24 };
        std::vector<long long> secondPreimageComplexitiesAVG(hashSizes.size(), 0);
        std::vector<long long> collisionComplexitiesAVG(hashSizes.size(), 0);
        std::vector<short> collisionsFound(hashSizes.size(), 1000);

        for (int i = 0; i < 1000; i++) {
            std::vector<long> secondPreimageComplexities;
            std::vector<long> collisionComplexities;

            std::vector<std::vector<std::string>> hashCollections = findSecondPreimages(md5.calcHash(randomString()),
                                                                                         hashSizes, secondPreimageComplexities);
            findCollisions(hashSizes,collisionComplexities, hashCollections);

            for (int j = 0; j < hashSizes.size(); j++) secondPreimageComplexitiesAVG[j] += secondPreimageComplexities[j];
            for (int j = 0; j < hashSizes.size(); j++) {
                if (collisionComplexities[j] == -1) collisionsFound[j] -= 1;
                else collisionComplexitiesAVG[j] += collisionComplexities[j];
            }
        }

        for (int i = 0; i < hashSizes.size(); i++) {
            secondPreimageComplexitiesAVG[i] /= 1000;
            collisionComplexitiesAVG[i] /= collisionsFound[i];
        }

        std::ofstream out;

        out.open("../etc/histogram_data/dependenceSecondPreimageComplexitiesAVG.txt");
        for (int i = 0; i < hashSizes.size(); i++) {
            if (out.is_open()) {
                out << hashSizes[i] << ";" << secondPreimageComplexitiesAVG[i] << "\n";
            }
        }
        out.close();
        out.clear();

        out.open("../etc/histogram_data/dependenceCollisionComplexitiesAVG.txt");
        for (int i = 0; i < hashSizes.size(); i++) {
            if (out.is_open()) {
                out << hashSizes[i] << ";" << collisionComplexitiesAVG[i] << "\n";
            }
        }
        out.close();
        out.clear();
    }

    return 0;
}
