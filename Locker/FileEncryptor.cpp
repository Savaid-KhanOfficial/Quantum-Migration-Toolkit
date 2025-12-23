#include "FileEncryptor.hpp"
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>

using namespace std;

vector<uint8_t> FileEncryptor::read_file(const string& path) {
    ifstream file(path, ios::binary);
    if (!file) {
        throw runtime_error("Failed to open file for reading: " + path);
    }
    
    // Read entire file into vector
    file.seekg(0, ios::end);
    size_t size = file.tellg();
    file.seekg(0, ios::beg);
    
    vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();
    
    return data;
}

void FileEncryptor::write_file(const string& path, const vector<uint8_t>& data) {
    ofstream file(path, ios::binary);
    if (!file) {
        throw runtime_error("Failed to open file for writing: " + path);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

vector<uint8_t> FileEncryptor::generate_iv() {
    vector<uint8_t> iv(16);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < iv.size(); i++) {
        iv[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return iv;
}

void FileEncryptor::encrypt_file(QuantumWrapper& quantum, const string& input_path, const string& output_path) {
    cout << "\n[FILE ENCRYPTOR] Starting quantum-safe encryption..." << endl;
    
    // Step 1: Get public key from the quantum wrapper
    vector<uint8_t> public_key = quantum.get_public_key();
    if (public_key.empty()) {
        throw runtime_error("No public key available. Generate or load keys first.");
    }
    
    // Step 2: Encapsulate to get shared secret (this will be used as AES key)
    cout << "  Performing key encapsulation..." << endl;
    auto [ciphertext, shared_secret] = quantum.encapsulate(public_key);
    
    // Step 4: Derive AES-256 key from shared secret (use first 32 bytes)
    vector<uint8_t> aes_key(32);
    if (shared_secret.size() >= 32) {
        copy(shared_secret.begin(), shared_secret.begin() + 32, aes_key.begin());
    } else {
        // If shared secret is smaller, pad with zeros
        copy(shared_secret.begin(), shared_secret.end(), aes_key.begin());
    }
    
    // Step 5: Generate random IV for AES
    vector<uint8_t> iv = generate_iv();
    
    // Step 6: Read the input file
    cout << "  Reading input file: " << input_path << endl;
    vector<uint8_t> plaintext = read_file(input_path);
    cout << "  File size: " << plaintext.size() << " bytes" << endl;
    
    // Step 7: Encrypt the file content with AES-256-CBC
    cout << "  Encrypting with AES-256-CBC..." << endl;
    vector<uint8_t> encrypted_data = AES::encrypt(plaintext, aes_key, iv);
    
    // Step 8: Build the output file structure:
    // [public_key_size(4)] [public_key] [ciphertext_size(4)] [ciphertext] 
    // [iv(16)] [encrypted_data_size(4)] [encrypted_data]
    vector<uint8_t> output;
    
    // Write public key size and data
    uint32_t pk_size = static_cast<uint32_t>(public_key.size());
    output.insert(output.end(), reinterpret_cast<uint8_t*>(&pk_size), reinterpret_cast<uint8_t*>(&pk_size) + 4);
    output.insert(output.end(), public_key.begin(), public_key.end());
    
    // Write ciphertext size and data
    uint32_t ct_size = static_cast<uint32_t>(ciphertext.size());
    output.insert(output.end(), reinterpret_cast<uint8_t*>(&ct_size), reinterpret_cast<uint8_t*>(&ct_size) + 4);
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    
    // Write IV (fixed 16 bytes)
    output.insert(output.end(), iv.begin(), iv.end());
    
    // Write encrypted data size and data
    uint32_t enc_size = static_cast<uint32_t>(encrypted_data.size());
    output.insert(output.end(), reinterpret_cast<uint8_t*>(&enc_size), reinterpret_cast<uint8_t*>(&enc_size) + 4);
    output.insert(output.end(), encrypted_data.begin(), encrypted_data.end());
    
    // Step 9: Write to output file
    cout << "  Writing encrypted file: " << output_path << endl;
    write_file(output_path, output);
    
    cout << "  Total encrypted file size: " << output.size() << " bytes" << endl;
    cout << "\n[SUCCESS] File encrypted successfully!" << endl;
}

void FileEncryptor::decrypt_file(QuantumWrapper& quantum, const string& input_path, const string& output_path) {
    cout << "\n[FILE DECRYPTOR] Starting quantum-safe decryption..." << endl;
    
    // Step 1: Read the encrypted file
    cout << "  Reading encrypted file: " << input_path << endl;
    vector<uint8_t> encrypted_file = read_file(input_path);
    
    size_t offset = 0;
    
    // Step 2: Extract public key
    uint32_t pk_size;
    memcpy(&pk_size, &encrypted_file[offset], 4);
    offset += 4;
    vector<uint8_t> public_key(encrypted_file.begin() + offset, encrypted_file.begin() + offset + pk_size);
    offset += pk_size;
    
    // Step 3: Extract ciphertext
    uint32_t ct_size;
    memcpy(&ct_size, &encrypted_file[offset], 4);
    offset += 4;
    vector<uint8_t> ciphertext(encrypted_file.begin() + offset, encrypted_file.begin() + offset + ct_size);
    offset += ct_size;
    
    // Step 4: Extract IV
    vector<uint8_t> iv(encrypted_file.begin() + offset, encrypted_file.begin() + offset + 16);
    offset += 16;
    
    // Step 5: Extract encrypted data
    uint32_t enc_size;
    memcpy(&enc_size, &encrypted_file[offset], 4);
    offset += 4;
    vector<uint8_t> encrypted_data(encrypted_file.begin() + offset, encrypted_file.begin() + offset + enc_size);
    
    // Step 6: Get secret key from quantum wrapper
    vector<uint8_t> secret_key = quantum.get_secret_key();
    if (secret_key.empty()) {
        throw runtime_error("No secret key available. Load keys first.");
    }
    
    // Step 7: Decapsulate to recover shared secret
    cout << "  Recovering shared secret..." << endl;
    vector<uint8_t> shared_secret = quantum.decapsulate(ciphertext, secret_key);
    
    // Step 8: Derive AES-256 key from shared secret
    vector<uint8_t> aes_key(32);
    if (shared_secret.size() >= 32) {
        copy(shared_secret.begin(), shared_secret.begin() + 32, aes_key.begin());
    } else {
        copy(shared_secret.begin(), shared_secret.end(), aes_key.begin());
    }
    
    // Step 9: Decrypt the data with AES-256-CBC
    cout << "  Decrypting with AES-256-CBC..." << endl;
    vector<uint8_t> plaintext = AES::decrypt(encrypted_data, aes_key, iv);
    
    // Step 10: Write the decrypted file
    cout << "  Writing decrypted file: " << output_path << endl;
    write_file(output_path, plaintext);
    
    cout << "  Decrypted file size: " << plaintext.size() << " bytes" << endl;
    cout << "\n[SUCCESS] File decrypted successfully!" << endl;
}
