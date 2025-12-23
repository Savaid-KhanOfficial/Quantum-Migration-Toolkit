#ifndef AES_HPP
#define AES_HPP

#include <vector>
#include <cstdint>

using namespace std;

class AES {
public:
    // Encrypt data using AES-256-CBC
    static vector<uint8_t> encrypt(const vector<uint8_t>& data, 
                                   const vector<uint8_t>& key, 
                                   const vector<uint8_t>& iv);
    
    // Decrypt data using AES-256-CBC
    static vector<uint8_t> decrypt(const vector<uint8_t>& data, 
                                   const vector<uint8_t>& key, 
                                   const vector<uint8_t>& iv);

private:
    // AES constants
    static const int AES_BLOCK_SIZE = 16;
    static const int AES_KEY_SIZE = 32;  // AES-256
    static const int NK = 8;  // Number of 32-bit words in key
    static const int NR = 14; // Number of rounds for AES-256
    
    // AES S-box
    static const uint8_t sbox[256];
    static const uint8_t inv_sbox[256];
    static const uint8_t rcon[11];
    
    // Core AES functions
    static void key_expansion(const uint8_t* key, uint8_t* round_keys);
    static void add_round_key(uint8_t* state, const uint8_t* round_key);
    static void sub_bytes(uint8_t* state);
    static void inv_sub_bytes(uint8_t* state);
    static void shift_rows(uint8_t* state);
    static void inv_shift_rows(uint8_t* state);
    static void mix_columns(uint8_t* state);
    static void inv_mix_columns(uint8_t* state);
    static void cipher(uint8_t* state, const uint8_t* round_keys);
    static void inv_cipher(uint8_t* state, const uint8_t* round_keys);
    static uint8_t gf_mul(uint8_t a, uint8_t b);
    
    // PKCS7 padding
    static vector<uint8_t> add_padding(const vector<uint8_t>& data);
    static vector<uint8_t> remove_padding(const vector<uint8_t>& data);
};

#endif // AES_HPP
