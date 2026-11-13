#pragma once

#include <array>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>


namespace crypto{
constexpr size_t KEY_SIZE = 32;     // 256 bits (AES-256 / X25519)
constexpr size_t PUBKEY_SIZE = 32;  // X25519 public key size
constexpr size_t PRIVKEY_SIZE = 32; // X25519 private key size
constexpr size_t IV_SIZE = 16;      // AES-CTR 128-bit IV/counter block

using Key256 = std::array<uint8_t, KEY_SIZE>;
using PubKey256 = std::array<uint8_t, PUBKEY_SIZE>;
using PrivKey256 = std::array<uint8_t, PRIVKEY_SIZE>;
using IV128 = std::array<uint8_t, IV_SIZE>;


struct X25519KeyPair{
    PubKey256 public_key{};
    PrivKey256 private_key{};
};


// generate an ephemeral X25519 keypair
inline bool generate_x25519_keypair(X25519KeyPair& keypair){
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if(!pctx){
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    bool success = false;
    if(EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_keygen(pctx, &pkey) > 0 && pkey){
        size_t pub_len = PUBKEY_SIZE;
        size_t priv_len = PRIVKEY_SIZE;
        if(EVP_PKEY_get_raw_public_key(pkey, keypair.public_key.data(), &pub_len) > 0 &&
           EVP_PKEY_get_raw_private_key(pkey, keypair.private_key.data(), &priv_len) > 0 &&
           pub_len == PUBKEY_SIZE && priv_len == PRIVKEY_SIZE){
            success = true;
        }
        EVP_PKEY_free(pkey);
    }
    EVP_PKEY_CTX_free(pctx);
    return success;
}


// derive a 32-byte shared secret from our private key and peer's public key using X25519 ECDH
inline bool derive_x25519_shared_secret(const PrivKey256& our_private_key,
                                        const PubKey256& peer_public_key,
                                        Key256& shared_secret){
    EVP_PKEY* priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                       our_private_key.data(),
                                                       our_private_key.size());
    if(!priv_pkey){
        return false;
    }

    EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                      peer_public_key.data(),
                                                      peer_public_key.size());
    if(!peer_pkey){
        EVP_PKEY_free(priv_pkey);
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_pkey, nullptr);
    bool success = false;
    if(ctx && EVP_PKEY_derive_init(ctx) > 0 &&
       EVP_PKEY_derive_set_peer(ctx, peer_pkey) > 0){
        size_t secret_len = shared_secret.size();
        if(EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) > 0 &&
           secret_len == shared_secret.size()){
            success = true;
        }
    }

    if(ctx){
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(priv_pkey);
    return success;
}


// derive a fixed 16-byte IV deterministically from a 32-byte key for stream cipher mode
inline IV128 derive_iv_from_key(const Key256& key){
    IV128 iv{};
    for(size_t i = 0; i < IV_SIZE; ++i){
        iv[i] = static_cast<uint8_t>(key[i] ^ key[i + IV_SIZE] ^ (0x5A + i));
    }
    return iv;
}


// encrypt/decrypt (symmetric stream cipher operation)
inline bool crypt_in_place_aes_ctr(const Key256& key, uint8_t* data, size_t len){
    if(!data || len == 0){
        return true;
    }

    IV128 iv = derive_iv_from_key(key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        return false;
    }

    bool success = false;
    if(EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data(), 1) == 1){
        int outlen = 0;
        if(EVP_CipherUpdate(ctx, data, &outlen, data, static_cast<int>(len)) == 1){
            int final_outlen = 0;
            if(EVP_CipherFinal_ex(ctx, data + outlen, &final_outlen) == 1){
                success = true;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}


// key exchange
struct EphemeralDH{
    X25519KeyPair keypair;
    bool initialized{false};


    EphemeralDH(){
        initialized = generate_x25519_keypair(keypair);
    }


    [[nodiscard]] const PubKey256& public_key() const{
        return keypair.public_key;
    }


    [[nodiscard]] bool compute_shared_secret(const PubKey256& peer_pubkey, Key256& out_shared_secret) const{
        if(!initialized){
            return false;
        }
        return derive_x25519_shared_secret(keypair.private_key, peer_pubkey, out_shared_secret);
    }
};


// helper functions
inline bool encrypt_layer_ce(const Key256& sh_ce, uint8_t* phdr_and_payload, size_t len) {
    return crypt_in_place_aes_ctr(sh_ce, phdr_and_payload, len);
}

inline bool decrypt_layer_ce(const Key256& sh_ce, uint8_t* phdr_and_payload, size_t len) {
    return crypt_in_place_aes_ctr(sh_ce, phdr_and_payload, len);
}

inline bool encrypt_layer_cr(const Key256& sh_cr, uint8_t* thdr_and_rest, size_t len) {
    return crypt_in_place_aes_ctr(sh_cr, thdr_and_rest, len);
}

inline bool decrypt_layer_cr(const Key256& sh_cr, uint8_t* thdr_and_rest, size_t len) {
    return crypt_in_place_aes_ctr(sh_cr, thdr_and_rest, len);
}

} // namespace crypto
