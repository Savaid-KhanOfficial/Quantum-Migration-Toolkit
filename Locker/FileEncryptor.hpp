#ifndef FILE_ENCRYPTOR_HPP
#define FILE_ENCRYPTOR_HPP

#include "QuantumKyber.hpp"
#include "AES.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>

using namespace std;

// Chunk size for streaming encryption/decryption (64 MB)
constexpr size_t CHUNK_SIZE = 64 * 1024 * 1024;

// File format (.qenc v2):
// [ciphertext_len (4B)] [ciphertext (Kyber KEM)]
// [iv (16B)]
// [encrypted_data (streamed AES-256-CBC)]
// [signature_len (4B)] [signature (Dilithium)]

class FileEncryptor {
public:
    // Encrypt a file using Quantum-safe key exchange + AES-256 (streaming)
    // Signs the ciphertext with Dilithium for integrity verification
    static void encrypt_file(QuantumWrapper& quantum, 
                             DilithiumWrapper& dilithium,
                             const string& input_path, 
                             const string& output_path);
    
    // Decrypt a file using Quantum-safe key exchange + AES-256 (streaming)
    // Verifies Dilithium signature before decryption
    static void decrypt_file(QuantumWrapper& quantum, 
                             DilithiumWrapper& dilithium,
                             const string& input_path, 
                             const string& output_path);

private:
    // Generate random IV for AES (using OpenSSL CSPRNG)
    static vector<uint8_t> generate_iv();
    
    // Stream encrypt file content in chunks
    static void stream_encrypt(ifstream& input, ofstream& output,
                               const vector<uint8_t>& key, 
                               const vector<uint8_t>& iv,
                               size_t input_size);
    
    // Stream decrypt file content in chunks
    static void stream_decrypt(ifstream& input, ofstream& output,
                               const vector<uint8_t>& key,
                               const vector<uint8_t>& iv,
                               size_t encrypted_size);
};

#endif // FILE_ENCRYPTOR_HPP
