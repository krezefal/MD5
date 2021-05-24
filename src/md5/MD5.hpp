/**
 * @author krezefal
 * Project on GitHub: https://github.com/krezefal/MD5
 */

#include <string>
#include <vector>

#include "../bigint/BigInt.hpp"

class MD5 {
private:

    static const short BYTES_NUM_IN_BLOCK = 4;

    uint32_t A = 0x67452302;
    uint32_t B = 0xefcdab89;
    uint32_t C = 0x98badcfe;
    uint32_t D = 0x10325476;

    unsigned int T[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                           0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                           0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                           0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                           0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                           0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                           0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                           0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                           0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                           0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                           0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                           0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                           0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                           0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                           0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                           0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

public:

    virtual std::string calcHash(const std::string& dataStreamByte) {

        BigInt inputDataSize = dataStreamByte.size();
        std::vector<uint32_t> dataStream32bit(dataStreamByte.size() / sizeof(uint32_t));

        for (int i = 0; i < dataStreamByte.size(); i += 4) {
            dataStream32bit[i] = _4bytesTo32Block(dataStreamByte, i);
        }

        dataStream32bit.push_back(0x80);
        do { dataStream32bit.push_back(0x00);
        } while (dataStreamByte.size() % 64 != 56);

        if (inputDataSize > UINT64_MAX - 1) {
            long leastBytes = (inputDataSize %= UINT64_MAX).to_long();
            long withoutLeast4Bytes = leastBytes & 0xFFFFFFFF;
            uint32_t least4Bytes = leastBytes ^ withoutLeast4Bytes;
            uint32_t high4Bytes = withoutLeast4Bytes >> 32;

            dataStream32bit.push_back(high4Bytes);
            dataStream32bit.push_back(least4Bytes);
        }
        else {
            long withoutLeast4Bytes = inputDataSize.to_long() & 0xFFFFFFFF;
            uint32_t least4Bytes = inputDataSize.to_long() ^ withoutLeast4Bytes;
            uint32_t high4Bytes = withoutLeast4Bytes >> 32;

            dataStream32bit.push_back(least4Bytes);
            dataStream32bit.push_back(high4Bytes);
        }

        std::vector<uint32_t> digest = MD5digest(dataStream32bit);
        std::string hash;

        for (uint32_t block : digest)
            hash += _32BlockTo4bytes(block);

        return hash;
    }

private:

    static uint32_t F(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Y | (~X) & Z); }
    static uint32_t G(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Z | (~Z) & Y); }
    static uint32_t H(uint32_t X, uint32_t Y, uint32_t Z) { return (X ^ Y ^ Z); }
    static uint32_t I(uint32_t X, uint32_t Y, uint32_t Z) { return (Y ^ ((~Z) | X)); }

    static uint32_t leftRotate(uint32_t block, uint32_t s) { return (block << s) | (block >> (32 - s)); }

    static uint32_t MD5round1(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t t) {
        return leftRotate((a + F(b, c, d) + x + t), s);
    }
    static uint32_t MD5round2(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t t) {
        return leftRotate((a + G(b, c, d) + x + t), s);
    }
    static uint32_t MD5round3(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t t) {
        return leftRotate((a + H(b, c, d) + x + t), s);
    }
    static uint32_t MD5round4(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t t) {
        return leftRotate((a + I(b, c, d) + x + t), s);
    }

    void resetRegisters() {
        A = 0x67452302;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;
    }

    std::vector<uint32_t> MD5digest(const std::vector<uint32_t>& dataStream32bit) {

        uint32_t X[16];
        std::vector<uint32_t> digest(sizeof(uint32_t) * 4);
        uint32_t AA, BB, CC, DD;

        for (int j = 0; j < dataStream32bit.size(); j += 16) {

            for (int k = 0; k < 16; k++) X[j] = dataStream32bit[j * 16 + k];

            AA = A;
            BB = B;
            CC = C;
            DD = D;

            A = D; D = C; C = B; B += MD5round1(A, B, C, D, X[0], 7, T[0]);
            A = D; D = C; C = B; B += MD5round1(D, A, B, C, X[1], 12, T[1]);
            A = D; D = C; C = B; B += MD5round1(C, D, A, B, X[2], 17, T[2]);
            A = D; D = C; C = B; B += MD5round1(B, C, D, A, X[3], 22, T[3]);
            A = D; D = C; C = B; B += MD5round1(A, B, C, D, X[4], 7, T[4]);
            A = D; D = C; C = B; B += MD5round1(D, A, B, C, X[5], 12, T[5]);
            A = D; D = C; C = B; B += MD5round1(C, D, A, B, X[6], 17, T[6]);
            A = D; D = C; C = B; B += MD5round1(B, C, D, A, X[7], 22, T[7]);
            A = D; D = C; C = B; B += MD5round1(A, B, C, D, X[8], 7, T[8]);
            A = D; D = C; C = B; B += MD5round1(D, A, B, C, X[9], 12, T[9]);
            A = D; D = C; C = B; B += MD5round1(C, D, A, B, X[10], 17, T[10]);
            A = D; D = C; C = B; B += MD5round1(B, C, D, A, X[11], 22, T[11]);
            A = D; D = C; C = B; B += MD5round1(A, B, C, D, X[12], 7, T[12]);
            A = D; D = C; C = B; B += MD5round1(D, A, B, C, X[13], 12, T[13]);
            A = D; D = C; C = B; B += MD5round1(C, D, A, B, X[14], 17, T[14]);
            A = D; D = C; C = B; B += MD5round1(B, C, D, A, X[15], 22, T[15]);

            A = D; D = C; C = B; B += MD5round2(A, B, C, D, X[1], 5, T[16]);
            A = D; D = C; C = B; B += MD5round2(D, A, B, C, X[6], 9, T[17]);
            A = D; D = C; C = B; B += MD5round2(C, D, A, B, X[11], 14, T[18]);
            A = D; D = C; C = B; B += MD5round2(B, C, D, A, X[0], 20, T[19]);
            A = D; D = C; C = B; B += MD5round2(A, B, C, D, X[5], 5, T[20]);
            A = D; D = C; C = B; B += MD5round2(D, A, B, C, X[10], 9, T[21]);
            A = D; D = C; C = B; B += MD5round2(C, D, A, B, X[15], 14, T[22]);
            A = D; D = C; C = B; B += MD5round2(B, C, D, A, X[4], 20, T[23]);
            A = D; D = C; C = B; B += MD5round2(A, B, C, D, X[9], 5, T[24]);
            A = D; D = C; C = B; B += MD5round2(D, A, B, C, X[14], 9, T[25]);
            A = D; D = C; C = B; B += MD5round2(C, D, A, B, X[3], 14, T[26]);
            A = D; D = C; C = B; B += MD5round2(B, C, D, A, X[8], 20, T[27]);
            A = D; D = C; C = B; B += MD5round2(A, B, C, D, X[13], 5, T[28]);
            A = D; D = C; C = B; B += MD5round2(D, A, B, C, X[2], 9, T[29]);
            A = D; D = C; C = B; B += MD5round2(C, D, A, B, X[7], 14, T[30]);
            A = D; D = C; C = B; B += MD5round2(B, C, D, A, X[12], 20, T[31]);

            A = D; D = C; C = B; B += MD5round3(A, B, C, D, X[5], 4, T[32]);
            A = D; D = C; C = B; B += MD5round3(D, A, B, C, X[8], 11, T[33]);
            A = D; D = C; C = B; B += MD5round3(C, D, A, B, X[11], 16, T[34]);
            A = D; D = C; C = B; B += MD5round3(B, C, D, A, X[14], 23, T[35]);
            A = D; D = C; C = B; B += MD5round3(A, B, C, D, X[1], 4, T[36]);
            A = D; D = C; C = B; B += MD5round3(D, A, B, C, X[4], 11, T[37]);
            A = D; D = C; C = B; B += MD5round3(C, D, A, B, X[7], 16, T[38]);
            A = D; D = C; C = B; B += MD5round3(B, C, D, A, X[10], 23, T[39]);
            A = D; D = C; C = B; B += MD5round3(A, B, C, D, X[13], 4, T[40]);
            A = D; D = C; C = B; B += MD5round3(D, A, B, C, X[0], 11, T[41]);
            A = D; D = C; C = B; B += MD5round3(C, D, A, B, X[3], 16, T[42]);
            A = D; D = C; C = B; B += MD5round3(B, C, D, A, X[6], 23, T[43]);
            A = D; D = C; C = B; B += MD5round3(A, B, C, D, X[9], 4, T[44]);
            A = D; D = C; C = B; B += MD5round3(D, A, B, C, X[12], 11, T[45]);
            A = D; D = C; C = B; B += MD5round3(C, D, A, B, X[15], 16, T[46]);
            A = D; D = C; C = B; B += MD5round3(B, C, D, A, X[2], 23, T[47]);

            A = D; D = C; C = B; B += MD5round4(A, B, C, D, X[0], 6, T[48]);
            A = D; D = C; C = B; B += MD5round4(D, A, B, C, X[7], 10, T[49]);
            A = D; D = C; C = B; B += MD5round4(C, D, A, B, X[14], 15, T[50]);
            A = D; D = C; C = B; B += MD5round4(B, C, D, A, X[5], 21, T[51]);
            A = D; D = C; C = B; B += MD5round4(A, B, C, D, X[12], 6, T[52]);
            A = D; D = C; C = B; B += MD5round4(D, A, B, C, X[3], 10, T[53]);
            A = D; D = C; C = B; B += MD5round4(C, D, A, B, X[10], 15, T[54]);
            A = D; D = C; C = B; B += MD5round4(B, C, D, A, X[1], 21, T[55]);
            A = D; D = C; C = B; B += MD5round4(A, B, C, D, X[8], 6, T[56]);
            A = D; D = C; C = B; B += MD5round4(D, A, B, C, X[15], 10, T[57]);
            A = D; D = C; C = B; B += MD5round4(C, D, A, B, X[6], 15, T[58]);
            A = D; D = C; C = B; B += MD5round4(B, C, D, A, X[13], 21, T[59]);
            A = D; D = C; C = B; B += MD5round4(A, B, C, D, X[4], 6, T[60]);
            A = D; D = C; C = B; B += MD5round4(D, A, B, C, X[11], 10, T[61]);
            A = D; D = C; C = B; B += MD5round4(C, D, A, B, X[2], 15, T[62]);
            A = D; D = C; C = B; B += MD5round4(B, C, D, A, X[9], 21, T[63]);

            A += AA;
            B += BB;
            C += CC;
            D += DD;
        }

        digest[0] = A;
        digest[1] = B;
        digest[2] = C;
        digest[3] = D;

        resetRegisters();

        return digest;
    }




    static uint32_t _4bytesTo32Block(const std::string& dataStreamByte, int beginIdx) {
        uint32_t block = 0x00;

        for (int i = 0; i < BYTES_NUM_IN_BLOCK; i++)
            block = block | (((uint32_t) (dataStreamByte[beginIdx + i])) << (8 * (3 - i)));
        return block;
    }

    static std::string _32BlockTo4bytes(uint32_t block) {
        std::vector<char> _4bytes;
        _4bytes.reserve(BYTES_NUM_IN_BLOCK);

        for (int j = 0; j < BYTES_NUM_IN_BLOCK; j++)
            _4bytes.push_back((char) (block >> (8 * (3 - j))));
        return std::string(_4bytes.begin(), _4bytes.end());
    }
};

