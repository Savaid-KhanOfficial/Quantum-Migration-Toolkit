#ifndef AES_HPP
#define AES_HPP

#include <vector>
#include <cstdint>

using namespace std;

class AES {
public:
    // Encrypt data using AES-256-CBC with OpenSSL
    static vector<uint8_t> encrypt(const vector<uint8_t>& data, 
                                   const vector<uint8_t>& key, 
                                   const vector<uint8_t>& iv);
    
    // Decrypt data using AES-256-CBC with OpenSSL
    static vector<uint8_t> decrypt(const vector<uint8_t>& data, 
                                   const vector<uint8_t>& key, 
                                   const vector<uint8_t>& iv);
};

#endif // AES_HPP
