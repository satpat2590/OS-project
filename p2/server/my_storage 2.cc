#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/file.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /*
    AuthTableEntry {
      std::string username;           // The name of the user
      std::vector<uint8_t> salt;      // The salt to use with the password
      std::vector<uint8_t> pass_hash; // The hashed password
      std::vector<uint8_t> content;   // The user's content
    }
  */

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;


  

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  /// @param admin   The administrator's username
  MyStorage(const std::string &fname, size_t buckets, size_t, size_t, size_t,
            double, size_t, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  bool addtoFile(FILE *pFile, const char *data, size_t bytes) {
    if (fwrite(data, sizeof(char), bytes, pFile) != bytes) {
      cerr << "Incorrect Number of Bytes written" << endl;
      return false;
    }

    if (fflush(pFile) != 0) {
      cerr << "fflush failed" << endl;
    }

    fsync(fileno(pFile));
    return true;
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD)
      return {false, RES_ERR_REQ_FMT, {}};

    std::vector<uint8_t> passData(LEN_PASSHASH);

    passData.insert(passData.end(), pass.begin(), pass.end());

    unsigned char salt[LEN_SALT];

    if (!RAND_bytes(salt, LEN_SALT))
      return {false, RES_ERR_REQ_FMT, {}};

    passData.insert(passData.end(), salt, salt + LEN_SALT);

    std::vector<uint8_t> hashPass(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, passData.data(), passData.size());
    SHA256_Final(hashPass.data(), &sha256);

    AuthTableEntry e{user, vector<uint8_t>(salt, salt + sizeof(salt)), hashPass, {}};
    if (!this->auth_table->insert(user, e, []() {}))
      return {false, RES_ERR_USER_EXISTS, {}};

    return {true, RES_OK, {}};

    // if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
    //   return {false, RES_ERR_REQ_FMT, {}};
    // }

    // std::vector<uint8_t> SALT(LEN_SALT);
    // int r = RAND_bytes(SALT.data(), SALT.size());

    // if (r == 0)
    //   cerr << "Error when creating salt:: cerr";
    

    // std::vector<uint8_t> toHash;  

    // toHash.insert(toHash.end(), pass.begin(), pass.end());
    // toHash.insert(toHash.end(), SALT.begin(), SALT.end());

    // std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // SHA256_Update(&sha256, toHash.data(), toHash.size());
    // SHA256_Final(hash.data(), &sha256);

    
    // AuthTableEntry newUser = {user, SALT, hash, {}};
    // if (!this->auth_table->insert(user, newUser, [] () {})) 
    //   return result_t{false, RES_ERR_USER_EXISTS, {}}; 
   

    // return result_t{true, RES_OK, {}};
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {

    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    if (!auth(user, pass).succeeded)
      return {false, RES_ERR_LOGIN, {}};

    if (this->auth_table->do_with(user, [&content](AuthTableEntry &val)
                                  { val.content = content; }))
      return {true, RES_OK, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(content.size() > 0);
  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    if (!auth(user, pass).succeeded)
      return {false, RES_ERR_LOGIN, {}};

    std::vector<uint8_t> content; 

    if (this->auth_table->do_with_readonly(who, [&content] (const AuthTableEntry &val) { content = val.content; })) {
      if (content.size() == 0)
        return {false, RES_ERR_NO_DATA, {}};
      else
        return {true, RES_OK, content}; //returns the content of the user you need from 
    } else
        return {false, RES_ERR_NO_USER, {}};


    
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(who.length() > 0);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
    //   return {false, RES_ERR_REQ_FMT, {}};
    // }
    // auto liar = auth(user, pass);
    // if (!liar.succeeded)
    //   return liar; // grrrrr we hate liars




    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    if (!auth(user, pass).succeeded)
      return {false, RES_ERR_LOGIN, {}};

    std::vector<uint8_t> data;

    this->auth_table->do_all_readonly([&data](const string &key, const AuthTableEntry &val)
                                      {
      data.insert(data.end(), key.begin(), key.end());
      data.insert(data.end(), 10);
      assert(val.username.length()); },
                                      []() {});

    if (data.size() == 0)
      return {false, RES_ERR_NO_DATA, {}};
    else
      return {true, RES_OK, data};

    return {false, RES_ERR_SERVER, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    std::string userG; 
    std::vector<uint8_t> saltG; 
    std::vector<uint8_t> passHashG;

    auto f = [&] (const AuthTableEntry &val) {
      userG = val.username;
      saltG = val.salt;
      passHashG = val.pass_hash;
    };

    bool status = this->auth_table->do_with_readonly(user, f);

    if (!status) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    if (user != userG) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

      vector<uint8_t> data(LEN_PASSHASH);
      data.insert(data.end(), pass.begin(), pass.end());
      data.insert(data.end(), saltG.begin(), saltG.end());
      vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, data.data(), data.size());
      SHA256_Final(hash.data(), &sha256);

    if (passHashG != hash) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    return result_t{true, RES_OK, {}};

    // bool auth = false;
    // if (this->auth_table->do_with_readonly(user, [&user, &pass, &auth](const AuthTableEntry &val) {
    //   cout << "\nuser: " << user.data() << "\npass: " << pass.data() << endl;
    //   cout << "\nuser from val: " << val.username.data() << "\npasshash from val: " << val.pass_hash.data() << endl;
    //   vector<uint8_t> data(LEN_PASSHASH);
    //   data.insert(data.begin(), pass.begin(), pass.end());
    //   data.insert(data.end(), val.salt.begin(), val.salt.end());
    //   vector<uint8_t> hash(LEN_PASSHASH);
    //   SHA256_CTX sha256;
    //   SHA256_Init(&sha256);
    //   SHA256_Update(&sha256, data.data(), data.size());
    //   SHA256_Final(hash.data(), &sha256);
    //   if (val.pass_hash == hash) auth = true; }))
    // {
    //   if (auth)
    //     return {true, RES_OK, {}};
    // }

    // return {false, RES_ERR_LOGIN, {}};
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    auto liar = auth(user, pass);
    if (!liar.succeeded)
      return liar; // grrrrr we hate liars


    if(!this->kv_store->insert(key, val, [] () {})) 
      return {false, RES_ERR_USER_EXISTS, {}};

    return {true, RES_OK, {}};
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
  }

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {

    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    auto liar = auth(user, pass);
    if (!liar.succeeded)
      return liar; // grrrrr we hate liars

    std::vector<uint8_t> content;

    if (this->kv_store->do_with_readonly(key, [&content] (const std::vector<uint8_t> &val)
                                           { content = val; })) {
      if (content.size() == 0)
        return {false, RES_ERR_NO_DATA, {}};
      else
        return {true, RES_OK, content}; // returns the content of the user you need from
    }
    else
      return {false, RES_ERR_NO_USER, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
  }

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {

    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) 
      return {false, RES_ERR_REQ_FMT, {}};
    

    auto liar = auth(user, pass);
    if (!liar.succeeded)
      return liar; // grrrrr we hate liars

    if (!this->kv_store->remove(key, [] () {} ))
      return {false, RES_ERR_KEY, {}};

    return {true, RES_OK, {}};
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
  }

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

      if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
        return {false, RES_ERR_REQ_FMT, {}};
      }

      auto liar = auth(user, pass);
      if (!liar.succeeded)
        return liar; // grrrrr we hate liars

      if (!this->kv_store->insert(key, val, [] () {})) 
        return {false, RES_ERR_USER_EXISTS, {}};
      
    return {true, RES_OK, {}};
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
  }

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    
    // NB: These asserts are to prevent compiler warnings
    return {false, RES_ERR_UNIMPLEMENTED, {}};
    assert(user.length() > 0);
    assert(pass.length() > 0); 
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    cout << "Server terminated";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {

    std::string filename = this->filename + ".tmp";

    FILE *pFile = fopen(filename.c_str(), "ab");

    if (pFile == nullptr) {
      cerr << "Cannot open '" << filename << "' for writing\n";
    }

    ContextManager closeThis([&]()
                             { fclose(pFile); });

    auto g = [&](const std::string &k, const std::vector<uint8_t> &v) {
      string KV = "KVKVKVKV";
      addtoFile(pFile, KV.data(), KV.length());
      // key size
      int keySize = k.length();
      addtoFile(pFile, (char *)&keySize, sizeof(int));
      // actual key
      addtoFile(pFile, k.data(), k.length());
      // size of value
      int valueSize = v.size();
      addtoFile(pFile, (char *)&valueSize, sizeof(int));
      // actual value
      addtoFile(pFile, (const char *)v.data(), v.size());
    };
};

/// Create an empty Storage object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
