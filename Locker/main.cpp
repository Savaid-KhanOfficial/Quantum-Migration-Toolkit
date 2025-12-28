#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include "FileEncryptor.hpp"

using namespace std;
namespace fs = filesystem;

// Display help menu
void show_help() {
    cout << "==========================================================" << endl;
    cout << "  QUANTUM LOCKER v2.0 - Command Line Tool" << endl;
    cout << "  Post-Quantum Cryptography File Protection" << endl;
    cout << "  Powered by Kyber-512 + AES-256 + Dilithium3" << endl;
    cout << "==========================================================" << endl;
    cout << "\nUSAGE:" << endl;
    cout << "  QuantumLocker <command> [arguments]" << endl;
    cout << "\nCOMMANDS:" << endl;
    cout << "  genkeys <identity_name>" << endl;
    cout << "      Generate quantum-safe keypair and save to:" << endl;
    cout << "        - <identity_name>.pub      (Kyber public key)" << endl;
    cout << "        - <identity_name>.priv     (Kyber private key)" << endl;
    cout << "        - <identity_name>.sig.pub  (Dilithium signing public key)" << endl;
    cout << "        - <identity_name>.sig.priv (Dilithium signing private key)" << endl;
    cout << "\n  encrypt <identity_name> <file_path>" << endl;
    cout << "      Encrypt and sign a file using your identity" << endl;
    cout << "        - Loads keys from <identity_name>.*" << endl;
    cout << "        - Encrypts <file_path> to <file_path>.qenc" << endl;
    cout << "        - Signs ciphertext with Dilithium for integrity" << endl;
    cout << "\n  decrypt <identity_name> <file_path.qenc>" << endl;
    cout << "      Verify and decrypt a quantum-encrypted file" << endl;
    cout << "        - Verifies Dilithium signature first" << endl;
    cout << "        - Decrypts to original filename (removes .qenc)" << endl;
    cout << "\nEXAMPLES:" << endl;
    cout << "  QuantumLocker genkeys alice" << endl;
    cout << "  QuantumLocker encrypt alice secret.txt" << endl;
    cout << "  QuantumLocker decrypt alice secret.txt.qenc" << endl;
    cout << "\nFILE FORMAT (.qenc v2):" << endl;
    cout << "  [Kyber Ciphertext] [IV] [Encrypted Data] [Dilithium Signature]" << endl;
    cout << "==========================================================" << endl;
}

// Command: Generate Keys
int cmd_genkeys(const string& identity_name) {
    try {
        cout << "\n[GENKEYS] Generating quantum-safe identity: " << identity_name << endl;
        
        // Generate Kyber KEM keypair
        cout << "\n--- Generating Kyber-512 Keypair (Encryption) ---" << endl;
        QuantumWrapper quantum;
        auto [public_key, secret_key] = quantum.generate_keypair();
        
        cout << "  Kyber Public Key:  " << public_key.size() << " bytes" << endl;
        cout << "  Kyber Secret Key:  " << secret_key.size() << " bytes" << endl;
        
        if (!quantum.save_keys(identity_name)) {
            cerr << "[ERROR] Failed to save Kyber keys" << endl;
            return 1;
        }
        
        // Generate Dilithium signature keypair
        cout << "\n--- Generating Dilithium3 Keypair (Signing) ---" << endl;
        DilithiumWrapper dilithium;
        auto [sig_public_key, sig_secret_key] = dilithium.generate_signature_keypair();
        
        if (!dilithium.save_keys(identity_name)) {
            cerr << "[ERROR] Failed to save Dilithium keys" << endl;
            return 1;
        }
        
        cout << "\n[SUCCESS] All keys generated and saved!" << endl;
        cout << "  ✓ " << identity_name << ".pub       (Kyber public key)" << endl;
        cout << "  ✓ " << identity_name << ".priv      (Kyber private key)" << endl;
        cout << "  ✓ " << identity_name << ".sig.pub   (Dilithium signing public key)" << endl;
        cout << "  ✓ " << identity_name << ".sig.priv  (Dilithium signing private key)" << endl;
        cout << "\nKeep your .priv and .sig.priv files safe and never share them!" << endl;
        
        return 0;
        
    } catch (const exception& e) {
        cerr << "[ERROR] " << e.what() << endl;
        return 1;
    }
}

// Command: Encrypt File
int cmd_encrypt(const string& identity_name, const string& file_path) {
    try {
        // Check if input file exists
        if (!fs::exists(file_path)) {
            cerr << "[ERROR] File not found: " << file_path << endl;
            return 1;
        }
        
        // Check if all key files exist
        if (!fs::exists(identity_name + ".pub") || !fs::exists(identity_name + ".priv")) {
            cerr << "[ERROR] Kyber identity not found: " << identity_name << endl;
            cerr << "  Run 'QuantumLocker genkeys " << identity_name << "' first" << endl;
            return 1;
        }
        
        if (!fs::exists(identity_name + ".sig.pub") || !fs::exists(identity_name + ".sig.priv")) {
            cerr << "[ERROR] Dilithium signing keys not found: " << identity_name << endl;
            cerr << "  Run 'QuantumLocker genkeys " << identity_name << "' first" << endl;
            return 1;
        }
        
        cout << "\n[ENCRYPT] Encrypting file: " << file_path << endl;
        cout << "  Using identity: " << identity_name << endl;
        
        // Load Kyber keys
        QuantumWrapper quantum;
        if (!quantum.load_keys(identity_name)) {
            cerr << "[ERROR] Failed to load Kyber keys" << endl;
            return 1;
        }
        
        // Load Dilithium signing keys
        DilithiumWrapper dilithium;
        if (!dilithium.load_keys(identity_name)) {
            cerr << "[ERROR] Failed to load Dilithium keys" << endl;
            return 1;
        }
        
        // Encrypt and sign file
        string output_path = file_path + ".qenc";
        FileEncryptor::encrypt_file(quantum, dilithium, file_path, output_path);
        
        cout << "\n[SUCCESS] File encrypted and signed!" << endl;
        cout << "  Input:  " << file_path << endl;
        cout << "  Output: " << output_path << endl;
        
        return 0;
        
    } catch (const exception& e) {
        cerr << "[ERROR] " << e.what() << endl;
        return 1;
    }
}
        
        return 0;
        
    } catch (const exception& e) {
        cerr << "[ERROR] " << e.what() << endl;
        return 1;
    }
}

// Command: Decrypt File
int cmd_decrypt(const string& identity_name, const string& file_path) {
    try {
        // Check if input file exists
        if (!fs::exists(file_path)) {
            cerr << "[ERROR] File not found: " << file_path << endl;
            return 1;
        }
        
        // Check if file ends with .qenc
        if (file_path.size() < 5 || file_path.substr(file_path.size() - 5) != ".qenc") {
            cerr << "[ERROR] File must have .qenc extension" << endl;
            return 1;
        }
        
        // Check if all key files exist
        if (!fs::exists(identity_name + ".pub") || !fs::exists(identity_name + ".priv")) {
            cerr << "[ERROR] Kyber identity not found: " << identity_name << endl;
            cerr << "  Make sure you have " << identity_name << ".pub and .priv" << endl;
            return 1;
        }
        
        if (!fs::exists(identity_name + ".sig.pub") || !fs::exists(identity_name + ".sig.priv")) {
            cerr << "[ERROR] Dilithium signing keys not found: " << identity_name << endl;
            cerr << "  Make sure you have " << identity_name << ".sig.pub and .sig.priv" << endl;
            return 1;
        }
        
        cout << "\n[DECRYPT] Decrypting file: " << file_path << endl;
        cout << "  Using identity: " << identity_name << endl;
        
        // Load Kyber keys
        QuantumWrapper quantum;
        if (!quantum.load_keys(identity_name)) {
            cerr << "[ERROR] Failed to load Kyber keys" << endl;
            return 1;
        }
        
        // Load Dilithium signing keys
        DilithiumWrapper dilithium;
        if (!dilithium.load_keys(identity_name)) {
            cerr << "[ERROR] Failed to load Dilithium keys" << endl;
            return 1;
        }
        
        // Remove .qenc extension for output
        string output_path = file_path.substr(0, file_path.size() - 5);
        
        // Verify signature and decrypt file
        FileEncryptor::decrypt_file(quantum, dilithium, file_path, output_path);
        
        cout << "\n[SUCCESS] File verified and decrypted!" << endl;
        cout << "  Input:  " << file_path << endl;
        cout << "  Output: " << output_path << endl;
        
        return 0;
        
    } catch (const exception& e) {
        cerr << "[ERROR] " << e.what() << endl;
        return 1;
    }
}

int main(int argc, char* argv[]) {
    // Check if no arguments provided
    if (argc < 2) {
        show_help();
        return 1;
    }
    
    string command = argv[1];
    
    // Parse commands
    if (command == "genkeys") {
        if (argc < 3) {
            cerr << "[ERROR] Missing argument: identity_name" << endl;
            cerr << "Usage: QuantumLocker genkeys <identity_name>" << endl;
            return 1;
        }
        return cmd_genkeys(argv[2]);
        
    } else if (command == "encrypt") {
        if (argc < 4) {
            cerr << "[ERROR] Missing arguments" << endl;
            cerr << "Usage: QuantumLocker encrypt <identity_name> <file_path>" << endl;
            return 1;
        }
        return cmd_encrypt(argv[2], argv[3]);
        
    } else if (command == "decrypt") {
        if (argc < 4) {
            cerr << "[ERROR] Missing arguments" << endl;
            cerr << "Usage: QuantumLocker decrypt <identity_name> <file_path.qenc>" << endl;
            return 1;
        }
        return cmd_decrypt(argv[2], argv[3]);
        
    } else if (command == "help" || command == "--help" || command == "-h") {
        show_help();
        return 0;
        
    } else {
        cerr << "[ERROR] Unknown command: " << command << endl;
        cerr << "Run 'QuantumLocker help' for usage information" << endl;
        return 1;
    }
}
