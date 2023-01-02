#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "requests.h"


using namespace std;

/*
  Padding '0' characters to the end of any passed data value. 

  Currently two implementation: 
    1. Takes a vector<uint8_t> msg and then uses push_back to add the values to the given padlen

    2. Takes a std::string and then uses operator+ overload command to concatenate strings 
*/

void pad0(std::vector<uint8_t> &msg, int padlen) {
  bool reached_cap = 0;
  for (int i = 0; (int)msg.size() < padlen; i++) {
    msg.push_back('\0');
    if ((int)msg.capacity() > padlen && !reached_cap) {
      //printf("At this iterator: %d, we reached 256 capacity..");
      reached_cap = 1;
    }
  }
}


/*
  Padding random bytes onto RSA-encrypted blocks of data. 

  This function uses the RAND_bytes call from the OpenSSL library to generate
  random bytes to pad the vector<uint8_t> msg. 
*/
void padR(std::vector<uint8_t> &msg, int padlen) {
  // REFERENCE: int RAND_bytes(unsigned char *buf, int num);
  int remainder = padlen - (int)msg.size();
  int i;
  unsigned char randbytes[remainder];
  if (!RAND_bytes(randbytes, remainder))
    cerr << "RAND_bytes failed to generate random bytes\n"; 

  // better implementation... 
  for (i = 0; i < remainder; i++) {
      msg.push_back(randbytes[i]);
  }
}


// Helper function to print out the vector to debug... [GDB is nice and all, but we love print statements <3]
void printVec(std::vector<uint8_t> &VectorPrint) {
  std::vector<uint8_t>::iterator it = VectorPrint.begin();
  while (it != VectorPrint.end()) {
    printf("%c", *it);
    printf(" ");
    it++;
  }
}

void better_insert(vector<uint8_t> &v, size_t i) {
  v.insert(v.end(), (uint8_t *)&i, ((uint8_t *)&i) + sizeof(size_t));
}

// // Used to place each len() value as an 8-byte representation using uint64_t casted into uint8_t* 
// void better_insert(vector<uint8_t> &v, uint64_t i) {
//   v.insert(v.end(), (uint8_t*)&i, ((uint8_t*)&i) + sizeof(uint64_t));
// }

// Used to easily place each given string value into a vector<uint8_t>                    
void better_insert(vector<uint8_t> &v, const string &s) {
  v.insert(v.end(), s.begin(), s.end());
}

void better_insert(vector<uint8_t> &v, const vector<uint8_t> &dubious_insert) {
  v.insert(v.end(), dubious_insert.begin(), dubious_insert.end());
}


std::vector<uint8_t> OBlockGang(EVP_CIPHER_CTX *ctx, const std::string &user, const std::string &pass) {
  // 1. Creating the unencrypted @ablock
  uint64_t man_this_better_work = (uint64_t) user.length();
  std::vector<uint8_t> da_holy_grail;
  da_holy_grail.reserve(LEN_PASSWORD + LEN_UNAME + 16);
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, user);
  man_this_better_work = (uint64_t) pass.length(); 
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, pass);
  da_holy_grail.shrink_to_fit();
  // 2. Encrypt the @ablock
  vector<uint8_t> ChiefKeefOBlock = aes_crypt_msg(ctx, da_holy_grail); // Encrypted @ablock

  return ChiefKeefOBlock; 
}

std::vector<uint8_t> OBlockGang(EVP_CIPHER_CTX *ctx, const std::string &user, const std::string &pass, const std::string &getname) {
  // 1. Creating the unencrypted @ablock
  size_t man_this_better_work = (size_t) user.length();
  std::vector<uint8_t> da_holy_grail;
  da_holy_grail.reserve(LEN_PASSWORD + LEN_UNAME + LEN_PROFILE_FILE + 24);
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, user);
  man_this_better_work = (size_t) pass.length(); 
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, pass);
  man_this_better_work = (size_t) getname.length();
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, getname);
  da_holy_grail.shrink_to_fit();
  // 2. Encrypt the @ablock
  vector<uint8_t> ChiefKeefOBlock = aes_crypt_msg(ctx, da_holy_grail); // Encrypted @ablock

  return ChiefKeefOBlock; 
}


std::vector<uint8_t> OBlockGang(EVP_CIPHER_CTX *ctx,  const std::string &user,  const std::string &pass, const std::vector<uint8_t> &content) {
  // 1. Creating the unencrypted @ablock
  uint64_t man_this_better_work = (uint64_t) user.length();
  std::vector<uint8_t> da_holy_grail;
  da_holy_grail.reserve(LEN_PASSWORD + LEN_UNAME + LEN_PROFILE_FILE + 24);
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, user);
  man_this_better_work = (uint64_t) pass.length(); 
  better_insert(da_holy_grail, man_this_better_work);
  better_insert(da_holy_grail, pass);
  man_this_better_work = (uint64_t) content.size();
  better_insert(da_holy_grail, man_this_better_work);
  da_holy_grail.insert(da_holy_grail.end(), content.begin(), content.end());
  da_holy_grail.shrink_to_fit();

  cout << "contents of da_holy_grail:\n" << (const char*) da_holy_grail.data() << endl;
  // 2. Encrypt the @ablock
  vector<uint8_t> ChiefKeefOBlock = aes_crypt_msg(ctx, da_holy_grail); // Encrypted @ablock

  return ChiefKeefOBlock; 
}


std::vector<uint8_t> RBlockYay(const std::string &cmd, std::vector<uint8_t> &holy_key, RSA *pub, uint64_t ablockLen) {
  // 1. Create the @rblock using the formula listed above... 
  std::vector<uint8_t> WatchOutKeef_ItsDaRBlock; // Unencrypted @rblock
  WatchOutKeef_ItsDaRBlock.reserve(LEN_RBLOCK_CONTENT);
  better_insert(WatchOutKeef_ItsDaRBlock, cmd);
  better_insert(WatchOutKeef_ItsDaRBlock, holy_key);
  better_insert(WatchOutKeef_ItsDaRBlock, ablockLen);
  padR(WatchOutKeef_ItsDaRBlock, LEN_RBLOCK_CONTENT);
  // 2. Create unsigned char toBuffer[LEN_RKBLOCK] and then encrypt Chief Keef's Opps
  unsigned char toBuffer[LEN_RKBLOCK];
  RSA_public_encrypt((int)WatchOutKeef_ItsDaRBlock.size(), WatchOutKeef_ItsDaRBlock.data(), toBuffer, pub, RSA_PKCS1_OAEP_PADDING); // For understanding: WatchOutKeef_ItsDaRBlock -> encryptedChiefKeefsOpps
  // 3. Transfer the encrypted bytes from the toBuffer to the actual vector<uint8_t> encryptedChiefKeefsOpps
  int i; 
  std::vector<uint8_t> encryptedChiefKeefsOpps; 
  encryptedChiefKeefsOpps.reserve(LEN_RKBLOCK);

  for (i = 0; i < LEN_RKBLOCK; i++) 
    encryptedChiefKeefsOpps.push_back(toBuffer[i]);
  
  ablockLen = (uint64_t)encryptedChiefKeefsOpps.size();
  return encryptedChiefKeefsOpps; 
}




/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  std::string poop = REQ_KEY;
  std::vector<uint8_t> key;
  key.insert(key.begin(), poop.begin(), poop.end());
  pad0(key, 256); //Padding the key block to send to the server. Must be 256 bytes
  if (!send_reliably(sd, key)) 
    cerr << "Error sending the aeskey to the server...";
  
  /*
    [@pubkey has a size of 426 bytes]
  */
  std::vector<uint8_t> decryptResponse;
  decryptResponse.reserve(LEN_RSA_PUBKEY); //Reserve length of RSA pubkey to return from server... [protocol.h]
  decryptResponse = reliable_get_to_eof(sd);
  if (!write_file(keyfile, decryptResponse, 0)) 
    cerr << "Error writing the RSA pubkey to the file...";

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(keyfile.length() > 0);
}



/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, RSA *pubkey, const string &user, const string &pass, const string &, const string &) {
  vector<uint8_t> holy_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(holy_key, true);
  std::vector<uint8_t> ablock;
  ablock.reserve(LEN_UNAME + LEN_PASSWORD + LEN_PROFILE_FILE + 16);
  ablock = OBlockGang(ctx, user, pass);
  std::vector<uint8_t> rblock;
  rblock.reserve(LEN_RBLOCK_CONTENT);
  rblock = RBlockYay(REQ_REG, holy_key, pubkey, ablock.size()); 
  better_insert(rblock, ablock);

  // Sending the encrypted @rblock first and then sending the encrypted @ablock
  if (!send_reliably(sd, rblock)) 
    cerr << "Error in sending rblock" << endl;

  std::vector<uint8_t> servResponse; 
  servResponse.reserve(holy_key.size() + 10);
  servResponse = reliable_get_to_eof(sd);

  if (!reset_aes_context(ctx, holy_key, false)) 
    cerr << "error in reset_aes_context" << endl;

  std::vector<uint8_t> decryptResponse = aes_crypt_msg(ctx, servResponse);

  cout << (const char *)decryptResponse.data() << endl;
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  vector<uint8_t> holy_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(holy_key, true);
  std::vector<uint8_t> ablock;
  ablock.reserve(LEN_UNAME + LEN_PASSWORD + LEN_PROFILE_FILE + 16);
  ablock = OBlockGang(ctx, user, pass);
  std::vector<uint8_t> rblock;
  rblock.reserve(LEN_RKBLOCK);
  rblock = RBlockYay(REQ_BYE, holy_key, pubkey, ablock.size());
  better_insert(rblock, ablock);
  // Sending the encrypted @rblock first and then sending the encrypted @ablock
  if (!send_reliably(sd, rblock))
    cerr << "Error sending reliably" << endl;
  std::vector<uint8_t> servResponse = reliable_get_to_eof(sd);

  if (!reset_aes_context(ctx, holy_key, false)) 
    cerr << "errors nahhhh" << endl;

  std::vector<uint8_t> decryptResponse = aes_crypt_msg(ctx, servResponse);

  cout << (const char *) decryptResponse.data() << endl; 

  // cout << (const char *)decryptResponse.data() << endl;
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  vector<uint8_t> holy_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(holy_key, true);
  std::vector<uint8_t> ablock;
  ablock.reserve(LEN_UNAME + LEN_PASSWORD + LEN_PROFILE_FILE + 16);
  ablock = OBlockGang(ctx, user, pass);
  std::vector<uint8_t> rblock;
  rblock.reserve(LEN_RKBLOCK);
  rblock = RBlockYay(REQ_SAV, holy_key, pubkey, ablock.size());

  better_insert(rblock, ablock);

  if (!send_reliably(sd, rblock))
    cerr << "grrr.. unreliable send grrrrr" << endl;

  std::vector<uint8_t> servResponse = reliable_get_to_eof(sd);

  if (!reset_aes_context(ctx, holy_key, false)) 
    cerr << "error nahhh " << endl;

  std::vector<uint8_t> decryptResponse = aes_crypt_msg(ctx, servResponse);

  cout << (const char*) decryptResponse.data() << endl;

  // cout << (const char *)decryptResponse.data() << endl;
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &setfile, const string &) {
  vector<uint8_t> holy_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(holy_key, 1);
  // Checking setfile existence and then placing into @b 
  if (file_exists(setfile)) {
    std::vector<uint8_t> informacionParaLosStorage;
    informacionParaLosStorage = load_entire_file(setfile);

    // cout << informacionParaLosStorage.data() << endl; 
    // cout << "\n\nSize of content: " << informacionParaLosStorage.size() << endl; 

    if (informacionParaLosStorage.size() > LEN_PROFILE_FILE) 
      cerr << "Bruvva! Da size of da content for monsieur server: " << informacionParaLosStorage.data() << endl;
    

    size_t man_this_better_work = (size_t) user.length();
    std::vector<uint8_t> da_holy_grail;
    better_insert(da_holy_grail, man_this_better_work);
    better_insert(da_holy_grail, user);
    man_this_better_work = (size_t)pass.length();
    better_insert(da_holy_grail, man_this_better_work);
    better_insert(da_holy_grail, pass);
    man_this_better_work = (size_t)informacionParaLosStorage.size();
    better_insert(da_holy_grail, man_this_better_work);
    da_holy_grail.insert(da_holy_grail.end(), informacionParaLosStorage.begin(), informacionParaLosStorage.end());


    // cout << "\n\n\n This is the Ablock: " << da_holy_grail.data() << endl;

    // cout << "contents of da_holy_grail:\n" << da_holy_grail.size() << endl;
    // 2. Encrypt the @ablock
    std::vector<uint8_t> ChiefKeefOBlock = aes_crypt_msg(ctx, da_holy_grail); // Encrypted @ablock

    std::vector<uint8_t> rblock;
    rblock.reserve(LEN_RKBLOCK);
    rblock = RBlockYay(REQ_SET, holy_key, pubkey, ChiefKeefOBlock.size());
    better_insert(rblock, ChiefKeefOBlock);


    if (!send_reliably(sd, rblock))
      cerr << "error in sending reliably unreliable... rblock: " << rblock.data() << endl;

    std::vector<uint8_t> servResponse = reliable_get_to_eof(sd);

    if (!reset_aes_context(ctx, holy_key, 0)) 
      cerr << "Error resetting AES context: Here's the key: " << (const char*) holy_key.data() << endl; 
    
    std::vector<uint8_t> decryptResponse = aes_crypt_msg(ctx, servResponse);
    cout << (const char*) decryptResponse.data() << endl;
  } else 
      cerr << "error, file does not exist" << endl;

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(setfile.length() > 0);
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &getname, const string &) {
  vector<uint8_t> holy_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(holy_key, 1);
  std::vector<uint8_t> ablock = OBlockGang(ctx, user, pass, getname);
  std::vector<uint8_t> rblock = RBlockYay(REQ_GET, holy_key, pubkey, ablock.size());
  better_insert(rblock, ablock);
  if (!send_reliably(sd, rblock))
    cerr << "error in sending reliably unreliable... rblock: " << rblock.data() << endl;

  std::vector<uint8_t> servResponse = reliable_get_to_eof(sd);

  if (!reset_aes_context(ctx, holy_key, 0)) 
    cerr << "error in resetting context line 446" << endl;

  std::vector<uint8_t> decryptResponse = aes_crypt_msg(ctx, servResponse);
  std::string s = getname + ".file.dat";

  // std::vector<uint8_t> finalResponse(decryptResponse.data(), decryptResponse.data() + 8);
  // size_t lenContent = *(size_t *)(decryptResponse.data() + 8); 
  // std::vector<uint8_t> purelyContent(decryptResponse.data() + 16, decryptResponse.data() + 16 + lenContent);

  std::string WORKPLEASE(decryptResponse.data(), decryptResponse.data() + 8);

  if (WORKPLEASE == RES_OK) {
    if (!write_file(s, decryptResponse, 16)) {
      cout << (const char*)decryptResponse.data() << endl;
    } else {
        cout << WORKPLEASE << endl;
    }
  }

  cout << (const char*) decryptResponse.data() << endl;

  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(getname.length() > 0);
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &allfile, const string &) {
  vector<uint8_t> holy_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(holy_key, 1);
  std::vector<uint8_t> ablock = OBlockGang(ctx, user, pass);
  std::vector<uint8_t> rblock = RBlockYay(REQ_ALL, holy_key, pubkey, ablock.size());
  better_insert(rblock, ablock);

  if (!send_reliably(sd, rblock))
    cerr << "bad boy! line 479 yoohoo!" << endl;

  std::vector<uint8_t> servResponse = reliable_get_to_eof(sd);

  if (!reset_aes_context(ctx, holy_key, 0)) 
    cerr << "error resetting context" << endl;

  std::vector<uint8_t> decryptResponse = aes_crypt_msg(ctx, servResponse);

  if (!write_file(allfile, decryptResponse, 16)) 
    cerr << "error writing to file" << endl;
  else {
    std::vector<uint8_t> finalResponse(decryptResponse.data(), decryptResponse.data() + 8);
    cout << (const char *)finalResponse.data() << endl;
  }
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(allfile.length() > 0);
}

