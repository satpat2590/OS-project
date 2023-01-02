#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

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

  Map<string, std::vector<uint8_t> > *kv_store; 

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
      : auth_table(authtable_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

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

    passData.insert(passData.begin(), pass.begin(), pass.end());

    unsigned char salt[LEN_SALT];

    if (!RAND_bytes(salt, LEN_SALT))
      return {false, RES_ERR_REQ_FMT, {}};



    passData.insert(passData.begin(), salt, salt + LEN_SALT);

    std::vector<uint8_t> hashPass(LEN_PASSHASH);
    SHA256_CTX sha256; 
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, passData.data(), passData.size());
    SHA256_Final(hashPass.data(), &sha256);

    AuthTableEntry e { user, vector<uint8_t>(salt, salt + sizeof(salt)), hashPass, {} };
    if (!this->auth_table->insert(user, e, [] () {}))
      return {false, RES_ERR_USER_EXISTS, {}};

    return {true, RES_OK, {}};
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

    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD || content.size() >= LEN_PROFILE_FILE) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    if (!auth(user, pass).succeeded)
      return {false, RES_ERR_LOGIN, {}};

    if (this->auth_table->do_with(user, [&content] (AuthTableEntry &val) { 
        val.content = content; 
    }))      
      return {true, RES_OK, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(content.size() > 0);
    return {false, RES_ERR_SERVER, {}};
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
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD)
    {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    if (!auth(user, pass).succeeded)
      return {false, RES_ERR_LOGIN, {}};

    std::vector<uint8_t> content; 

    if (this->auth_table->do_with_readonly(who, [&content](const AuthTableEntry &val)
                                  { content = val.content; })) {
      if (content.size() == 0) 
        return {false, RES_ERR_NO_DATA, {}};
        else
          return {true, RES_OK, content};
      } else return {false, RES_ERR_NO_USER, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(content.size() > 0);
    return {false, RES_ERR_SERVER, {}};
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    if (!auth(user, pass).succeeded)
      return {false, RES_ERR_LOGIN, {}};


    std::vector<uint8_t> data; 

    this->auth_table->do_all_readonly([&data] (const string &key, const AuthTableEntry &val) {
      data.insert(data.end(), key.begin(), key.end());
      data.insert(data.end(), 10);
      assert(val.username.length());
    }, [] () {});

    if (data.size() == 0)
      return {false, RES_ERR_NO_DATA, {}};
    else
      return {true, RES_OK, data};

    return {false, RES_ERR_SERVER, {}};

    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
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

    bool auth = false;
    if (this->auth_table->do_with_readonly(user, [&user, &pass, &auth] (const AuthTableEntry &val) {
      vector<uint8_t> data(LEN_PASSHASH);
      data.insert(data.begin(), pass.begin(), pass.end());
      data.insert(data.end(), val.salt.begin(), val.salt.end());
      vector<uint8_t> hash(LEN_PASSHASH);
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, data.data(), data.size());
      SHA256_Final(hash.data(), &sha256);
      if (val.pass_hash == hash) auth = true; 
    })) {
      if (auth)
        return {true, RES_OK, {}};
    }
    
    return {false, RES_ERR_LOGIN, {}};
  
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    cout << "my_storage.cc::shutdown() is not implemented\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    cout << "my_storage.cc::save_file() is not implemented\n";
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }

    cout << "my_storage.cc::load_file() is not implemented\n";
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }
  
};

/// Create an empty Storage object and specify the file from which it should be
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
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
