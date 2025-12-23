// Legacy authentication system
#include <openssl/rsa.h>
#include <openssl/md5.h>

class AuthSystem {
public:
    // WARNING: Using RSA encryption
    void encrypt_with_rsa() {
        RSA *rsa = RSA_new();
        // RSA key generation
    }
    
    // WARNING: Using MD5 for password hashing
    void hash_password() {
        MD5_CTX ctx;
        // MD5 hashing - INSECURE!
    }
};
