#ifndef QUANTUM_KYBER_HPP
#define QUANTUM_KYBER_HPP

#include <oqs/oqs.h>
#include <vector>
#include <utility>
#include <stdexcept>
#include <cstdint>

using namespace std;

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

#endif // QUANTUM_KYBER_HPP
