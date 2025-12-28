#ifndef QUANTUM_KYBER_HPP
#define QUANTUM_KYBER_HPP

#include <oqs/oqs.h>
#include <vector>
#include <utility>
#include <stdexcept>
#include <cstdint>
#include <string>

using namespace std;

// ============================================================================
// QuantumWrapper - Kyber KEM for key encapsulation
// ============================================================================
class QuantumWrapper {
private:
    OQS_KEM* kem;
    vector<uint8_t> stored_public_key;
    vector<uint8_t> stored_secret_key;
    
public:
    // Constructor: initializes KEM with given algorithm (default: Kyber-512)
    QuantumWrapper(const char* alg_name = OQS_KEM_alg_kyber_512);
    
    // Destructor: cleans up KEM resources
    ~QuantumWrapper();
    
    // Generates a keypair and returns (public_key, secret_key)
    pair<vector<uint8_t>, vector<uint8_t>> generate_keypair();
    
    // Encapsulates: generates ciphertext and shared secret using public key
    pair<vector<uint8_t>, vector<uint8_t>> encapsulate(vector<uint8_t> public_key);
    
    // Decapsulates: recovers shared secret using ciphertext and secret key
    vector<uint8_t> decapsulate(vector<uint8_t> ciphertext, vector<uint8_t> secret_key);
    
    // Save keys to files (creates .pub and .priv files)
    bool save_keys(const string& filename_prefix);
    
    // Load keys from files (reads .pub and .priv files)
    bool load_keys(const string& filename_prefix);
    
    // Get stored public key
    vector<uint8_t> get_public_key() const { return stored_public_key; }
    
    // Get stored secret key
    vector<uint8_t> get_secret_key() const { return stored_secret_key; }
};

// ============================================================================
// DilithiumWrapper - ML-DSA Digital Signatures (Dilithium)
// ============================================================================
class DilithiumWrapper {
private:
    OQS_SIG* sig;
    vector<uint8_t> stored_public_key;
    vector<uint8_t> stored_secret_key;
    
public:
    // Constructor: initializes signature scheme (default: Dilithium3 / ML-DSA-65)
    DilithiumWrapper(const char* alg_name = OQS_SIG_alg_dilithium_3);
    
    // Destructor: cleans up signature resources
    ~DilithiumWrapper();
    
    // Generate a signature keypair and returns (public_key, secret_key)
    pair<vector<uint8_t>, vector<uint8_t>> generate_signature_keypair();
    
    // Sign a message using the stored secret key
    vector<uint8_t> sign_message(const vector<uint8_t>& message);
    
    // Sign a message using a provided secret key
    vector<uint8_t> sign_message(const vector<uint8_t>& message, const vector<uint8_t>& secret_key);
    
    // Verify a signature using the stored public key
    bool verify_signature(const vector<uint8_t>& message, const vector<uint8_t>& signature);
    
    // Verify a signature using a provided public key
    bool verify_signature(const vector<uint8_t>& message, const vector<uint8_t>& signature, 
                          const vector<uint8_t>& public_key);
    
    // Save signature keys to files (creates .sig.pub and .sig.priv files)
    bool save_keys(const string& filename_prefix);
    
    // Load signature keys from files
    bool load_keys(const string& filename_prefix);
    
    // Get stored public key
    vector<uint8_t> get_public_key() const { return stored_public_key; }
    
    // Get stored secret key
    vector<uint8_t> get_secret_key() const { return stored_secret_key; }
    
    // Get maximum signature length
    size_t get_signature_length() const;
};

#endif // QUANTUM_KYBER_HPP
