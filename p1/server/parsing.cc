#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "parsing.h"
#include "responses.h"

using namespace std;


bool is_kblock(std::vector<uint8_t> &msg) {
  string key_check(msg.begin(), msg.begin() + REQ_KEY.length());
  return key_check == REQ_KEY;
}


/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to possibly send to the client
/// @param storage The Storage object with which clients interact
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, RSA *pri, const vector<uint8_t> &pub,
                   Storage *storage) {

  std::vector<uint8_t> encryptedRSA(256);
  std::vector<uint8_t> welcomehomeR;

  // cout << "HIT 1\n\n";

  int bytes_received = reliable_get_to_eof_or_n(sd, encryptedRSA.begin(), 256); // getting the @rblock back

  // cout << "Bytes from RSA retrieval: " << bytes_received << endl;

  if (is_kblock(encryptedRSA)) {
    // cout << "KEY MADE FIRST\n\n" << endl;
    return handle_key(sd, pub);
  }

  // cout << "HIT 2\n\n";

  if (bytes_received == 0) {
    cerr << "No bytes received from @rblock" << endl;
  }
  unsigned char RSA_temp[LEN_RKBLOCK]; // Length of @rblock AFTER DECRYPTION 

  // cout << "HIT 3\n\n\n"<< endl; 
  RSA_private_decrypt(encryptedRSA.size(), encryptedRSA.data(), RSA_temp, pri, RSA_PKCS1_OAEP_PADDING);
  for (int i = 0; i < LEN_RKBLOCK; i++) {
    welcomehomeR.push_back(RSA_temp[i]);
  }

  // cout << "HIT 4\n\n\n" << endl;
  std::string CMD(welcomehomeR.data(), welcomehomeR.data() + 8); // std::string initalization beats insert()... 


  // cout << "\n\n\n\nCMD: " << CMD.c_str() << endl; 

  std::vector<uint8_t> aeskey(welcomehomeR.data() + 8, welcomehomeR.data() + 56);

  size_t len = *(size_t *)(welcomehomeR.data() + 56); // length of the @ablock using size_t casting instead of eightbytecastback

  std::vector<uint8_t> welcomehomeA(len);

  // cout << "HIT 5\n\n\n" << endl;
  if (!reliable_get_to_eof_or_n(sd, welcomehomeA.begin(), len))
    cerr << "Error in receiving aBlock" << endl;


  // std::vector<uint8_t> welcomehomeA;
  // reliable_get_to_eof_or_n(sd, welcomehomeA.begin(), len); // getting the @ablock back

  EVP_CIPHER_CTX *ctx = create_aes_context(aeskey, false);
  std::vector<uint8_t> aBlock = aes_crypt_msg(ctx, welcomehomeA);

  if (!reset_aes_context(ctx, aeskey, true)) 
    cerr << "Error in resetting context.." << endl;

  std::vector<std::string> comm = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav,
                                  handle_set, handle_get, handle_all};

  for (size_t i = 0; i < comm.size(); ++i)
    if (CMD == comm[i])
      return cmds[i](sd, storage, ctx, aBlock);

  // NB: These assertions are only here to prevent compiler warnings
  assert(pri);
  assert(storage);
  assert(pub.size() > 0);
  assert(sd);

  return false;
}
