#include "QuantumKyber.hpp"
#include <iostream>
#include <fstream>

using namespace std;

// Constructor: Initialize the KEM with the specified algorithm
QuantumWrapper::QuantumWrapper(const char* alg_name) {
    // Initialize liboqs
    OQS_init();
    
    // Check if the algorithm is enabled
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        OQS_destroy();
        throw runtime_error(string("Algorithm ") + alg_name + " is not enabled");
    }
    
    // Create the KEM object
    kem = OQS_KEM_new(alg_name);
    if (kem == nullptr) {
        OQS_destroy();
        throw runtime_error(string("Failed to create KEM for algorithm ") + alg_name);
    }
    
    cout << "QuantumWrapper initialized with algorithm: " << alg_name << endl;
}

// Destructor: Clean up resources
QuantumWrapper::~QuantumWrapper() {
    if (kem != nullptr) {
        OQS_KEM_free(kem);
        kem = nullptr;
    }
    OQS_destroy();
}

// Generate a keypair
pair<vector<uint8_t>, vector<uint8_t>> QuantumWrapper::generate_keypair() {
    if (kem == nullptr) {
        throw runtime_error("KEM is not initialized");
    }
    
    // Allocate memory for public and secret keys
    vector<uint8_t> public_key(kem->length_public_key);
    vector<uint8_t> secret_key(kem->length_secret_key);
    
    // Generate the keypair
    OQS_STATUS status = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to generate keypair");
    }
    
    // Store keys internally
    stored_public_key = public_key;
    stored_secret_key = secret_key;
    
    return make_pair(public_key, secret_key);
}

// Encapsulate: Generate ciphertext and shared secret from public key
pair<vector<uint8_t>, vector<uint8_t>> QuantumWrapper::encapsulate(vector<uint8_t> public_key) {
    if (kem == nullptr) {
        throw runtime_error("KEM is not initialized");
    }
    
    // Allocate memory for ciphertext and shared secret
    vector<uint8_t> ciphertext(kem->length_ciphertext);
    vector<uint8_t> shared_secret(kem->length_shared_secret);
    
    // Perform encapsulation
    OQS_STATUS status = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(), public_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to encapsulate");
    }
    
    return make_pair(ciphertext, shared_secret);
}

// Decapsulate: Recover shared secret from ciphertext using secret key
vector<uint8_t> QuantumWrapper::decapsulate(vector<uint8_t> ciphertext, vector<uint8_t> secret_key) {
    if (kem == nullptr) {
        throw runtime_error("KEM is not initialized");
    }
    
    // Allocate memory for shared secret
    vector<uint8_t> shared_secret(kem->length_shared_secret);
    
    // Perform decapsulation
    OQS_STATUS status = OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), secret_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to decapsulate");
    }
    
    return shared_secret;
}

// Save keys to files
bool QuantumWrapper::save_keys(const string& filename_prefix) {
    if (stored_public_key.empty() || stored_secret_key.empty()) {
        cerr << "No keys to save. Generate keys first." << endl;
        return false;
    }
    
    // Save public key
    string pub_filename = filename_prefix + ".pub";
    ofstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for writing" << endl;
        return false;
    }
    pub_file.write(reinterpret_cast<const char*>(stored_public_key.data()), stored_public_key.size());
    pub_file.close();
    
    // Save secret key
    string priv_filename = filename_prefix + ".priv";
    ofstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for writing" << endl;
        return false;
    }
    priv_file.write(reinterpret_cast<const char*>(stored_secret_key.data()), stored_secret_key.size());
    priv_file.close();
    
    cout << "Keys saved to " << pub_filename << " and " << priv_filename << endl;
    return true;
}

// Load keys from files
bool QuantumWrapper::load_keys(const string& filename_prefix) {
    if (kem == nullptr) {
        cerr << "KEM is not initialized" << endl;
        return false;
    }
    
    // Load public key
    string pub_filename = filename_prefix + ".pub";
    ifstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for reading" << endl;
        return false;
    }
    
    pub_file.seekg(0, ios::end);
    size_t pub_size = pub_file.tellg();
    pub_file.seekg(0, ios::beg);
    
    stored_public_key.resize(pub_size);
    pub_file.read(reinterpret_cast<char*>(stored_public_key.data()), pub_size);
    pub_file.close();
    
    // Load secret key
    string priv_filename = filename_prefix + ".priv";
    ifstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for reading" << endl;
        return false;
    }
    
    priv_file.seekg(0, ios::end);
    size_t priv_size = priv_file.tellg();
    priv_file.seekg(0, ios::beg);
    
    stored_secret_key.resize(priv_size);
    priv_file.read(reinterpret_cast<char*>(stored_secret_key.data()), priv_size);
    priv_file.close();
    
    cout << "Keys loaded from " << pub_filename << " and " << priv_filename << endl;
    return true;
}
