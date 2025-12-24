#include "AES.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

using namespace std;

vector<uint8_t> AES::encrypt(const vector<uint8_t>& data, const vector<uint8_t>& key, const vector<uint8_t>& iv) {
    if (key.size() != 32) {
        throw runtime_error("AES-256 requires a 32-byte key");
    }
    if (iv.size() != 16) {
        throw runtime_error("IV must be 16 bytes");
    }
    
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }
    
    // Initialize encryption operation with AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptInit_ex failed");
    }
    
    // Allocate output buffer (plaintext size + block size for padding)
    vector<uint8_t> encrypted(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;
    
    // Encrypt the data
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), static_cast<int>(data.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;
    
    // Finalize encryption (handles padding)
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize to actual encrypted length
    encrypted.resize(ciphertext_len);
    return encrypted;
}

vector<uint8_t> AES::decrypt(const vector<uint8_t>& data, const vector<uint8_t>& key, const vector<uint8_t>& iv) {
    if (key.size() != 32) {
        throw runtime_error("AES-256 requires a 32-byte key");
    }
    if (iv.size() != 16) {
        throw runtime_error("IV must be 16 bytes");
    }
    
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }
    
    // Initialize decryption operation with AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex failed");
    }
    
    // Allocate output buffer
    vector<uint8_t> decrypted(data.size());
    int len = 0;
    int plaintext_len = 0;
    
    // Decrypt the data
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data.data(), static_cast<int>(data.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;
    
    // Finalize decryption (handles padding removal)
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptFinal_ex failed - possibly incorrect key or corrupted data");
    }
    plaintext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize to actual decrypted length
    decrypted.resize(plaintext_len);
    return decrypted;
}
