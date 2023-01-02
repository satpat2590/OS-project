#include <cassert>
#include <iostream>
#include <string>

#include "../common/crypto.h"
#include "../common/net.h"

#include "responses.h"

using namespace std;


// Helper function to print out the vector to debug... [GDB is nice and all, but we love print statements <3]
void printVec(std::vector<uint8_t> &VectorPrint) {
  std::vector<uint8_t>::iterator it = VectorPrint.begin();
  while (it != VectorPrint.end()) {
    printf("%c", *it);
    printf(" ");
    it++;
  }
}

void printString(std::string &StringPrint) {
  std::string::iterator it = StringPrint.begin();
  while (it != StringPrint.end())
  {
    printf("%c", *it);
    printf(" ");
    it++;
  }
}
int maybeEightByteCastback(std::vector<uint8_t> &please) {
  uint64_t val = *(uint64_t *)please.data();
  please.clear();
  cout << "EightByteCallback: " << val << endl;
  return val;
}


/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_all(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &vec) {
  std::vector<uint8_t> response; // response to the client's request
  response.reserve(100);
  size_t len = *(size_t *)(vec.data());
  std::string name(vec.data() + 8, vec.data() + 8 + len);
  size_t len_pass = *(size_t *)(vec.data() + 8 + name.length());
  std::string pass(vec.data() + 16 + name.length(), vec.data() + 16 + name.length() + len_pass);

  if (!storage->auth(name, pass).succeeded) {
    cerr << "auth failed... " << name.c_str() << endl;
    send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_LOGIN));
  } else {
      auto tup = storage->get_all_users(name, pass);
      if (tup.succeeded) {
        response.insert(response.begin(), tup.msg.begin(), tup.msg.end());
        size_t get_len = tup.data.size();
        response.insert(response.end(), (uint8_t *)(&get_len), ((uint8_t *)&get_len) + sizeof(get_len));
        response.insert(response.end(), tup.data.begin(), tup.data.end());
        send_reliably(sd, aes_crypt_msg(ctx, response));
      } else {
          send_reliably(sd, aes_crypt_msg(ctx, tup.msg));
    }
  }

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(vec.size() > 0);
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_set(int sd, Storage *storage, EVP_CIPHER_CTX *ctx, const vector<uint8_t> &vec) {
  std::vector<uint8_t> response; // content to set & response to the client's request
  response.reserve(100);
  size_t len = *(size_t *)(vec.data());
  std::string name(vec.data() + 8, vec.data() + 8 + len);
  size_t len_pass = *(size_t *)(vec.data() + 8 + name.length());
  std::string pass(vec.data() + 16 + name.length(), vec.data() + 16 + name.length() + len_pass);
  size_t da_len = *(size_t *)(vec.data() + 16 + name.length() + pass.length());
  std::vector<uint8_t> content(vec.data() + 24 + name.length() + pass.length(), vec.data() + 24 + name.length() + da_len + pass.length());
  if (!storage->set_user_data(name, pass, content).succeeded) {
    response = aes_crypt_msg(ctx, RES_ERR_LOGIN);
    cerr << "set_user_data failed..." << endl;
  } else {
      response = aes_crypt_msg(ctx, RES_OK);
  }

  if (!send_reliably(sd, response))
    cerr << "Ohh nah mama this aint right! Send that handle_reg: send response command once more :D";

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(vec.size() > 0);
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_get(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &vec) {
  std::vector<uint8_t> response; // content to set & response to the client's request
  response.reserve(100);
  size_t len = *(size_t *)(vec.data());
  std::string name(vec.data() + 8, vec.data() + 8 + len);
  size_t len_pass = *(size_t *)(vec.data() + 8 + name.length());
  std::string pass(vec.data() + 16 + name.length(), vec.data() + 16 + name.length() + len_pass);
  size_t da_len = *(size_t *)(vec.data() + 16 + name.length() + pass.length());
  std::string getname(vec.data() + 24 + name.length() + pass.length(), vec.data() + 24 + name.length() + da_len + pass.length());

  if (storage->auth(name, pass).succeeded) { // must auth for correct client before storage calls
    auto tup = storage->get_user_data(name, pass, getname);
    if (!tup.succeeded) {
      send_reliably(sd, aes_crypt_msg(ctx, tup.msg)); // failed get_user_data
    } else {
        response.insert(response.begin(), tup.msg.begin(), tup.msg.end());
        size_t get_len = tup.data.size();
        response.insert(response.end(), (uint8_t *)(&get_len), ((uint8_t *)&get_len) + sizeof(get_len));
        response.insert(response.end(), tup.data.begin(), tup.data.end());
        send_reliably(sd, aes_crypt_msg(ctx, response));
    }
  } else
      send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_LOGIN)); // if auth failed.. 

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(vec.size() > 0);
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_reg(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &vec) {
  std::vector<uint8_t> response; // response to the client's request
  response.reserve(100);
  size_t len = *(size_t *)(vec.data());
  std::string name(vec.data() + 8, vec.data() + 8 + len);
  size_t len_pass = *(size_t *)(vec.data() + 8 + name.length());
  std::string pass(vec.data() + 16 + name.length(), vec.data() + 16 + name.length() + len_pass);

  if (!storage->add_user(name, pass).succeeded) {
    cerr << "Ohh nah mama this aint right! Send that handle_reg: add user command once more :D";
    response = aes_crypt_msg(ctx, RES_ERR_USER_EXISTS);
  } else {
      response = aes_crypt_msg(ctx, RES_OK);
  }

  if (!send_reliably(sd, response))
    cerr << "Ohh nah mama this aint right! Send that handle_reg: send response command once more :D";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(vec.size() > 0);
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
///
/// @return false, to indicate that the server shouldn't stop
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  if (!send_reliably(sd, pubfile))
    cerr << "how did u not send the inital key man cmon..";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubfile.size() > 0);
  return false;
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return true, to indicate that the server should stop, or false on an error
bool handle_bye(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &vec) {
  size_t len = *(size_t *)(vec.data());
  std::string name(vec.data() + 8, vec.data() + 8 + len);
  size_t len_pass = *(size_t *)(vec.data() + 8 + name.length());
  std::string pass(vec.data() + 16 + name.length(), vec.data() + 16 + name.length() + len_pass);
  std::vector<uint8_t> response; 

  auto tup = storage->auth(name, pass);
  if (!tup.succeeded) {
    cerr << "Ohh nah mama this aint right! Send that handle_reg: add user command once more :D";
    response = aes_crypt_msg(ctx, RES_ERR_LOGIN);
  } else {
      storage->shutdown();
      send_reliably(sd, aes_crypt_msg(ctx, RES_OK));
      return true;
  }

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(vec.size() > 0);
  return false;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_sav(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &vec) {
  size_t len = *(size_t *)(vec.data());
  std::string name(vec.data() + 8, vec.data() + 8 + len);
  size_t len_pass = *(size_t *)(vec.data() + 8 + name.length());
  std::string pass(vec.data() + 16 + name.length(), vec.data() + 16 + name.length() + len_pass);
  std::vector<uint8_t> response; 

  auto tup = storage->auth(name, pass);

  if (!tup.succeeded) {
    cerr << "Ohh nah mama this aint right! Send that handle_reg: add user command once more :D";
    response = aes_crypt_msg(ctx, RES_ERR_LOGIN);
    send_reliably(sd, response);
  } else {
      if (storage->save_file().succeeded) {
        response = aes_crypt_msg(ctx, RES_OK);
        send_reliably(sd, response);
    } else
        send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_SERVER)); 
  }


  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(vec.size() > 0);
  return false;
}