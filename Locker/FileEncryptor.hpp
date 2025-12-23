#ifndef FILE_ENCRYPTOR_HPP
#define FILE_ENCRYPTOR_HPP

#include "QuantumKyber.hpp"
#include "AES.hpp"
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

class FileEncryptor {
public:
    // Encrypt a file using Quantum-safe key exchange + AES-256
    static void encrypt_file(QuantumWrapper& quantum, const string& input_path, const string& output_path);
    
    // Decrypt a file using Quantum-safe key exchange + AES-256
    static void decrypt_file(QuantumWrapper& quantum, const string& input_path, const string& output_path);

private:
    // Helper function to read file content
    static vector<uint8_t> read_file(const string& path);
    
    // Helper function to write file content
    static void write_file(const string& path, const vector<uint8_t>& data);
    
    // Generate random IV for AES
    static vector<uint8_t> generate_iv();
};

#endif // FILE_ENCRYPTOR_HPP
