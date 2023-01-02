#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>

#include "err.h"

using namespace std;

// Helper function to print out the vector to debug... [GDB is nice and all, but we love print statements <3]
void printVec(std::vector<uint8_t> VectorPrint) {
  std::vector<uint8_t>::iterator it = VectorPrint.begin();
  printf("\n\n\n");
  while (it != VectorPrint.end()){
    printf("%c", *it);
    printf(" ");
    it++;
  }
  printf("\n\n\n");
}

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// again until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operation
/// @param msg A buffer of bytes to encrypt/decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
vector<uint8_t> aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start, int count) {

  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
  std::vector<uint8_t> out_buffo(count + cipher_block_size);

  int len, len_out = 0, len_final = 0;

  if (!EVP_CipherUpdate(ctx, out_buffo.data() + len_out, &len, start, count)) {
    cerr << "Improper EVP_CipherUpdate, rework it";
    return {};
  }

  len_out += len;

  if (1 != EVP_CipherFinal_ex(ctx, out_buffo.data() + len_out, &len_final)) {
    cerr << "Improper EVP_CipherUpdate, rework it";
    return {};
  }

  out_buffo.resize(len_out + len_final);

  return out_buffo;
    // These asserts are just for preventing compiler warnings:
    assert(ctx);
    assert(start);
    assert(count != -100);
  }
