#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <mutex>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/file.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "persist.h"
#include "storage.h"

using namespace std;

/// Pass in an open file and a data source to write to that file... 
///
/// FUNCTION NOT USED : ISSUES WITH PARAMETERS? FFLUSH ISSUES? 
///
/// @param pFile  The open file to write to
/// @param data   Data to write to the file
/// @param bytes  Number of bytes to write 
/// 
/// @return       true if successful write, false otherwise
bool addtoFile(FILE *pFile, const char *data, size_t bytes, const char* filename) {
  pFile = fopen(filename, "a");
  if (fwrite(data, sizeof(char), bytes, pFile) != bytes) {
    cerr << "Incorrect Number of Bytes written" << endl;
    return false;
  }

  if (fflush(pFile) != 0) {
    cerr << "Failure in addToFile: fflush(pFile)" << endl;
  }

  fsync(fileno(pFile));
  return true;
}

/// Pass in an open file and this function will extract all bytes and pass
/// return into a vector<uint8_t> 
/// 
/// 
///
/// @param pFile  The open file to write to
///
/// @return       Populated vector<uint8_t> if read() works, empty otherwise
std::vector<uint8_t> readFromFile(FILE *file) {
  std::vector<uint8_t> fileReceive;
  fseek(file, 0, SEEK_END);
  long lSize = ftell(file);
  rewind(file);
  char buffer[lSize];
  size_t result = fread(buffer, sizeof(uint8_t), lSize, file);
  if (result != lSize) {
    std::cerr << "Error reading from file" << std::endl;
    return {};
  }

  fileReceive.insert(fileReceive.end(), (char *)&buffer, (char *)&buffer + lSize);
  return fileReceive;
}

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;



  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

  /// The open file
  FILE *storage_file = nullptr;
  
  std::mutex storage_lock;
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

    AuthTableEntry ae{user, vector<uint8_t>(salt, salt + sizeof(salt)), hashPass, {}};

    if (!this->auth_table->insert(user, ae, [&] () {
      /*
        Logging:
        - AUTHAUTH
        - 8 BYTE USER LENGTH
        - USER 
        - 8 BYTE SALT LEN 
        - SALT
        - 8 BYTE PASS HASH LEN 
        - PASS HASH
        - 8 BYTE CONTENT LEN
        - CONTENT

        - PADDING = 8 - (SIZE OF ABOVE % 8)
      */
      std::vector<uint8_t> finalData;
      std::string authCmd = "AUTHAUTH";

      finalData.insert(finalData.end(), authCmd.begin(), authCmd.end()); //AUTHAUTH

      size_t userNameSize = ae.username.length();
      finalData.insert(finalData.end(), (char*)&userNameSize, ((char*)&userNameSize) + sizeof(size_t)); //LEN USER

      finalData.insert(finalData.end(), ae.username.begin(), ae.username.end()); //USER

      size_t saltSize = ae.salt.size();
      finalData.insert(finalData.end(), (char*)&saltSize, ((char*)&saltSize) + sizeof(size_t)); //LEN SALT

      finalData.insert(finalData.end(), ae.salt.begin(), ae.salt.end()); //SALT

      size_t passHashSize = ae.pass_hash.size();
      finalData.insert(finalData.end(), (char*)&passHashSize, ((char*)&passHashSize) + sizeof(size_t)); //LEN PASS HASH

      finalData.insert(finalData.end(), ae.pass_hash.begin(),  ae.pass_hash.end()); //PASS HASH

      size_t contentSize = ae.content.size();
      finalData.insert(finalData.end(), (char *)&contentSize, ((char*)&contentSize) + sizeof(size_t)); //LEN CONTENT
      //actual content 
      finalData.insert(finalData.end(), ae.content.begin(), ae.content.end()); //CONTENT

      // add padding
      if ((finalData.size() % 8) > 0) {
        size_t pads = 8 - (finalData.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          finalData.push_back(0);
        }
      }

      // add new data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(finalData.data(), sizeof(uint8_t), finalData.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

      // addtoFile(storage_file, (const char*)finalData.data(), finalData.size(), this->filename.c_str());
    })) {
      return {false, RES_ERR_USER_EXISTS, {}};
    }

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

    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }


    auto f = [&] (AuthTableEntry &ae) { 
      ae.content = content; //setting the AuthTableEntry content to our vector<uint8_t> &content

      /*
        Logging:
        - AUTHDIFF
        - 8 BYTE USER LENGTH
        - USER
        - 8 BYTE CONTENT LEN
        - CONTENT

        - PADDING = 8 - (SIZE OF ABOVE % 8)
      */
      std::vector<uint8_t> finalData; 

      finalData.insert(finalData.begin(), AUTHDIFF.begin(), AUTHDIFF.end()); //STORE AUTHDIFF

      size_t userNameSize = ae.username.length();
      finalData.insert(finalData.end(), (char *)&userNameSize, ((char*)&userNameSize) + sizeof(size_t)); //STORE USERNAME LENGTH

      finalData.insert(finalData.end(), ae.username.begin(), ae.username.end()); //STORE USERNAME


      size_t contentSize = ae.content.size();
      finalData.insert(finalData.end(), (char *)&contentSize, ((char*)&contentSize) + sizeof(size_t)); //STORE CONTENT LENGTH
   

      finalData.insert(finalData.end(), ae.content.begin(), ae.content.end()); //STORE CONTENT

      // add padding
      if ((finalData.size() % 8) > 0) {
        size_t pads = 8 - (finalData.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          finalData.push_back(0);
        }
      }

      // add new data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(finalData.data(), sizeof(uint8_t), finalData.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

      //addtoFile(storage_file, (const char*)finalData.data(), finalData.size(), this->filename.c_str());

    };

    this->auth_table->do_with(user, f); // apply the function f

    return result_t{true, RES_OK, {}};
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
  virtual result_t get_user_data(const string &user, const string &pass, const string &who) {

    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    std::vector<uint8_t> receivedData;

    // set all lambdas into auto variables in order to allow readablility
    auto f = [&receivedData] (const AuthTableEntry &ae) {
        receivedData = ae.content;
    };

  
    bool pleaseWork = this->auth_table->do_with_readonly(who, f);

    if (receivedData.empty()) {
      return result_t{false, RES_ERR_NO_DATA, {}};
    }

    if (!pleaseWork) {
      return result_t{false, RES_ERR_NO_USER, {}};
    }

    return result_t{true, RES_OK, receivedData};
  
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
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN , {}};
    }

    /*
      Returns a vector with all usernames in the AuthTable
      MUST BE NEWLINE DELIMITED
    */
    std::vector<uint8_t> allUsers;

    auto f = [&] (const string key, const AuthTableEntry &ae) {
      allUsers.insert(allUsers.end(), ae.username.begin(), ae.username.end());
      allUsers.push_back('\n'); //TEST FURTHER... 10 VS NEWLINE
    };

    auto fNo = [](){};
    
    this->auth_table->do_all_readonly(f, fNo);

    return result_t{true, RES_OK , allUsers};
  
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

    bool pleaseWork = this->auth_table->do_with_readonly(user, f);

    if (!pleaseWork) {
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
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {} };
    }
    //once the user is authenticated insert the key value

    bool pleaseWork = this->kv_store->insert(key, val, [&] () {
        /*
          Logging:
          - KVKVKVKV
          - 8 BYTE KEY LENGTH
          - KEY 
          - 8 BYTE VAL LEN 
          - VAL

          - PADDING = 8 - (SIZE OF ABOVE % 8)
        */
        std::vector<uint8_t> finalData; 

        finalData.insert(finalData.end(), KVENTRY.begin(), KVENTRY.end()); //KVKVKVKV

        size_t keySize = key.length();
        finalData.insert(finalData.end(), (char *)&keySize, ((char*)&keySize) + sizeof(size_t)); //LEN KEY

        finalData.insert(finalData.end(), key.begin(), key.end()); //KEY

        size_t valueSize = val.size();
        finalData.insert(finalData.end(), (char *)&valueSize, ((char *)&valueSize) + sizeof(size_t)); //LEN VAL

        finalData.insert(finalData.end(), val.begin(), val.end()); //VAL

        if ((finalData.size() % 8) > 0) { //PADDING
          size_t pads = 8 - (finalData.size() % 8);
          for (size_t i = 0; i < pads; i++) {
            finalData.push_back(0);
          }
        }

        // add new data to storage_file
        storage_file = fopen(filename.c_str(), "a");
        if (storage_file != nullptr) {
          fwrite(finalData.data(), sizeof(uint8_t), finalData.size(), storage_file);
          fflush(storage_file);
          fsync(fileno(storage_file));
        }

        //addtoFile(this->storage_file, (const char*)finalData.data(), finalData.size(), this->filename.c_str()); 
    });

    if (!pleaseWork) {
      return result_t{false, RES_ERR_KEY, {} }; 
    } else {
        return result_t{true, RES_OK, {} }; 
    }
  
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
    std::vector<uint8_t> valReturn; 
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    auto f = [&] (const std::vector<uint8_t> &val) {
      valReturn = val; 
    };

    bool thisisSparta = this->kv_store->do_with_readonly(key, f);

    if (!thisisSparta) {
      return result_t{false, RES_ERR_KEY, {}};
    }

    return result_t{true, RES_OK, valReturn};

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
  virtual result_t kv_delete(const string &user, const string &pass, const string &key) {
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {} };
    }

    bool pleaseWork = this->kv_store->remove(key, [&] () {
      /*
        Logging:
        - KVDELETE
        - 8 BYTE KEY LENGTH
        - KEY 

        - PADDING = 8 - (SIZE OF ABOVE % 8)
      */
      std::vector<uint8_t> finalData; 

      finalData.insert(finalData.end(), KVDELETE.begin(), KVDELETE.end()); //KVDELETE

      size_t keySize = key.length();
      finalData.insert(finalData.end(), (char*)&keySize, ((char *)&keySize) + sizeof(size_t)); //KEY LEN

      finalData.insert(finalData.end(), key.begin(), key.end()); //KEY

      size_t pad = 0;
      if ((finalData.size() % 8) > 0) { //PADDING
        size_t pads = 8 - (finalData.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          finalData.push_back(pad);
        }
      }

      // add new data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(finalData.data(), sizeof(uint8_t), finalData.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

      //addtoFile(this->storage_file, (const char*)finalData.data(), finalData.size(), this->filename.c_str()); //FLUSH CHANGES 
    }); 

    if (!pleaseWork) {
      return result_t{false, RES_ERR_KEY, {} }; 
    }

    return result_t{true, RES_OK, {} }; 

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
  virtual result_t kv_upsert(const string &user, const string &pass, const string &key, const vector<uint8_t> &val) {
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    bool pleaseWork = this->kv_store->upsert(key, val,
        [&] () { //insert
        /*
          Logging:
          - KVKVKVKV
          - 8 BYTE KEY LENGTH
          - KEY 
          - 8 BYTE VAL LEN 
          - VAL

          - PADDING = 8 - (SIZE OF ABOVE % 8)
        */
          std::vector<uint8_t> finalData; 

          finalData.insert(finalData.end(), KVENTRY.begin(), KVENTRY.end()); //KVKVKVKV

          size_t keySize = key.length();
          finalData.insert(finalData.end(), (char *)&keySize, ((char *)&keySize) + sizeof(size_t)); //LEN KEY

          finalData.insert(finalData.end(), key.begin(), key.end()); //KEY

          size_t valueSize = val.size();
          finalData.insert(finalData.end(), (char *)&valueSize, ((char *)&valueSize) + sizeof(size_t)); //LEN VAL

          finalData.insert(finalData.end(), val.begin(), val.end()); //VAL

          if ((finalData.size() % 8) > 0) { //PADDING
            size_t pads = 8 - (finalData.size() % 8);
            for (size_t i = 0; i < pads; i++) {
              finalData.push_back(0);
            }
          }

          // add new data to storage_file
          storage_file = fopen(filename.c_str(), "a");
          if (storage_file != nullptr) {
            fwrite(finalData.data(), sizeof(uint8_t), finalData.size(), storage_file);
            fflush(storage_file);
            fsync(fileno(storage_file));
          }
        },

        [&] () { //upsert 
        /*
          Logging:
          - KVUPDATE
          - 8 BYTE KEY LENGTH
          - KEY 
          - 8 BYTE VAL LEN 
          - VAL

          - PADDING = 8 - (SIZE OF ABOVE % 8)
        */
          std::vector<uint8_t> finalData;

          finalData.insert(finalData.end(), KVUPDATE.begin(), KVUPDATE.end()); //KVUPDATE

          size_t keySize = key.length();
          finalData.insert(finalData.end(), (char*)&keySize, (char*)&keySize + sizeof(size_t)); //LEN KEY

          finalData.insert(finalData.end(), key.begin(), key.end()); //KEY

          size_t valueSize = val.size();
          finalData.insert(finalData.end(), (char*)&valueSize, (char*)&valueSize + sizeof(size_t)); //LEN VAL

          finalData.insert(finalData.end(), val.begin(), val.end()); //VAL
          
          //addtoFile(storage_file, (const char*)finalData.data(), finalData.size(), this->filename.c_str()); //FLUSH CHANGES

          if ((finalData.size() % 8) > 0) { // PADDING
            size_t pads = 8 - (finalData.size() % 8);
            for (size_t i = 0; i < pads; i++) {
              finalData.push_back(0);
            }
          }

          // add new data to storage_file
          storage_file = fopen(filename.c_str(), "a");
          if (storage_file != nullptr) {
            fwrite(finalData.data(), sizeof(uint8_t), finalData.size(), storage_file);
            fflush(storage_file);
            fsync(fileno(storage_file));
          }

          // if (fflush(this->storage_file) != 0) { //CHECK FLUSH AGAIN
          //   cerr << "Failure in kv_upsert fflush(this->storage_file)" << endl;
          // }
      });

    if (!pleaseWork) {
      return result_t{true, RES_OKUPD, {}}; 
    }

    return result_t{true, RES_OKINS, {}}; 

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
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    std::vector<uint8_t> resultHolder; 

    auto f = [&] (const std::string key, const std::vector<uint8_t> &val) {
      resultHolder.insert(resultHolder.end(), key.begin(), key.end());
      resultHolder.push_back('\n');
    };

    auto fNo = [](){};

    this->kv_store->do_all_readonly(f, fNo);


    if (resultHolder.empty()) {
      return result_t{false, RES_ERR_NO_DATA, {}};
    }

    return result_t{true, RES_OK, resultHolder};
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    fflush(storage_file);
    fsync(fileno(storage_file));
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    std::vector<uint8_t> sentData;
    std::vector<uint8_t> kvStore;
    std::string tempFile = this->filename + ".tmp";
    FILE* tempOpen = fopen(tempFile.c_str(), "w+b");

    auto f = [&] (std::string name, const AuthTableEntry &ae) {
      size_t user_len = name.size();
      size_t salt_len = ae.salt.size();
      size_t pass_len = ae.pass_hash.size();
      size_t cont_len = ae.content.size();

      sentData.insert(sentData.end(), AUTHENTRY.begin(), AUTHENTRY.end()); //AUTHAUTH

      sentData.insert(sentData.end(), (char *)&user_len, ((char *)&user_len) + sizeof(size_t)); //LEN USER
      sentData.insert(sentData.end(), name.begin(), name.end()); //USER

      sentData.insert(sentData.end(), (char *)&salt_len, ((char *)&salt_len) + sizeof(size_t)); //LEN SALT
      sentData.insert(sentData.end(), ae.salt.begin(), ae.salt.end()); //SALT

      sentData.insert(sentData.end(), (char *)&pass_len, ((char *)&pass_len) + sizeof(size_t)); //LEN PASS HASH
      sentData.insert(sentData.end(), ae.pass_hash.begin(), ae.pass_hash.end()); //PASS HASH

      sentData.insert(sentData.end(), (char *)&cont_len, ((char *)&cont_len) + sizeof(size_t)); //LEN CONTENT
      sentData.insert(sentData.end(), ae.content.begin(), ae.content.end()); //CONTENT

      size_t pad = 0;
      if ((sentData.size() % 8) > 0) { //PADDING
        size_t pads = 8 - (sentData.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          sentData.push_back(pad);
        }
      }
    };

    auto g = [&] (std::string key, const std::vector<uint8_t> &val) {
      size_t key_len = key.size();
      size_t val_len = val.size();

      kvStore.insert(kvStore.end(), KVENTRY.begin(), KVENTRY.end());

      kvStore.insert(kvStore.end(), (char *)&key_len, ((char *)&key_len) + sizeof(size_t));
      kvStore.insert(kvStore.end(), key.begin(), key.end());

      kvStore.insert(kvStore.end(), (char *)&val_len, ((char *)&val_len) + sizeof(size_t));
      kvStore.insert(kvStore.end(), val.begin(), val.end());


      // add padding
      size_t pad = 0;
      if ((kvStore.size() % 8) > 0) {
        size_t pads = 8 - (kvStore.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          kvStore.push_back(pad);
        }
      }
    };

    auto gFin = [&] () {

    };

    // lambda function for chaining of auth table and KV store
    auto fChain = [&] () {

      this->kv_store->do_all_readonly(g, gFin);
    };

    auth_table->do_all_readonly(f, fChain);

    sentData.insert(sentData.end(), kvStore.begin(), kvStore.end());

    // add new data to storage_file
    tempOpen = fopen(tempFile.c_str(), "a");
    fwrite(sentData.data(), sizeof(uint8_t), sentData.size(), tempOpen);
    fflush(tempOpen);
    fsync(fileno(tempOpen));
    

    //addtoFile(tempOpen, (const char*)sentData.data(), sentData.size(), tempFile.c_str());

    rename(tempFile.c_str(), filename.c_str());

    return result_t{true, RES_OK, {}};
  }


  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {

    // std::lock_guard<std::mutex> lock(this->storage_lock);

    storage_file = fopen(filename.c_str(), "r"); //open to read
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }

    this->auth_table->clear();
    this->kv_store->clear();

    std::vector<uint8_t> receivedData = readFromFile(storage_file); //reading from file

    size_t index = 0;
    std::string whichCmd;

    while (index < receivedData.size()) { //start loop through received data

      for (size_t i = 0; i < 8; i++) {
        whichCmd += receivedData.at(index);
        index += 1;
      }

      if (whichCmd.compare(AUTHENTRY) == 0) { 
          //initalize all of AuthTableEntry data to pull
          std::string userActual;
          std::vector<uint8_t> saltActual; 
          std::vector<uint8_t> hashedPassActual; 
          std::vector<uint8_t> contentActual;

          size_t user_len = *(size_t *)(receivedData.data() + index);
          index += 8;

          userActual.insert(userActual.end(), receivedData.begin() + index, receivedData.begin() + index + user_len);
          index += user_len; //if our user length is equivalent to user, then increment index... 
          
          size_t salt_len = *(size_t *)(receivedData.data() + index);
          index += 8;

          saltActual.insert(saltActual.end(), receivedData.begin() + index, receivedData.begin() + index + salt_len);
          index += salt_len;    //if our salt length is equivalent to user, then increment index... 
          
          size_t hashed_len = *(size_t *)(receivedData.data() + index);
          index += 8;

          hashedPassActual.insert(hashedPassActual.end(), receivedData.begin() + index, receivedData.begin() + index + hashed_len);
          index += hashed_len; //if our user length is equivalent to user, then increment index... 
          
          size_t content_len = *(size_t *)(receivedData.data() + index);
          index += 8;

          contentActual.insert(contentActual.end(), receivedData.begin() + index, receivedData.begin() + index + content_len);
          index += content_len;

          /*
            taking pointer position at end of AUTHAUTH entry and finding length of one singular log
              by subtracting by initial position prior to the cmd entry 
          */
          size_t totalSize = content_len + hashed_len + salt_len + user_len + 40;

          if ((totalSize % 8) > 0) {
            int padding_Amt = 8 - (totalSize % 8); // incremented index by padding amount... should be aligned with next entry
            index += padding_Amt;
          }

          //create "val" for the auth_table... 
          AuthTableEntry newGuyinTown;
          newGuyinTown.username = userActual;
          newGuyinTown.salt = saltActual;
          newGuyinTown.pass_hash = hashedPassActual;
          newGuyinTown.content = contentActual;

          this->auth_table->insert(userActual, newGuyinTown, [](){});
      }

      else if (whichCmd.compare(KVENTRY) == 0) {

        std::string key;
        std::vector<uint8_t> valVec;

        size_t len_key = *(size_t *)(receivedData.data() + index);
        index += 8;

        key.insert(key.end(), receivedData.begin() + index, receivedData.begin() + index + len_key);
        index += len_key;

        size_t len_val = *(size_t *)(receivedData.data() + index);
        index += 8;

        valVec.insert(valVec.end(), receivedData.begin() + index, receivedData.begin() + index + len_val);
        index += len_val;

        /*
          taking pointer position at end of AUTHAUTH entry and finding length of one singular log
            by subtracting by initial position prior to the cmd entry
        */
        size_t totalSize = 24 + len_key + len_val;

        if ((totalSize % 8) > 0) {
          int padding_Amt = 8 - (totalSize % 8); // incremented index by padding amount... should be aligned with next entry
          index += padding_Amt;
        }

        this->kv_store->insert(key, valVec, [](){});
      }

      else if (whichCmd.compare(AUTHDIFF) == 0) {
          std::string userActual;
          std::vector<uint8_t> contentActual; 

          size_t user_len = *(size_t *)(receivedData.data() + index);
          index += 8;

          userActual.insert(userActual.end(), receivedData.begin() + index, receivedData.begin() + index + user_len);
          index += user_len; // if our user length is equivalent to user, then increment index...

          size_t content_len = *(size_t *)(receivedData.data() + index);
          index += 8;

          contentActual.insert(contentActual.end(), receivedData.begin() + index, receivedData.begin() + index + content_len);
          index += content_len;


          size_t totalSize = 24 + user_len + content_len;

          if ((totalSize % 8) > 0) {
            size_t padding_Amt = 8 - (totalSize % 8); // incremented index by padding amount... should be aligned with next entry
            index += padding_Amt;
          }

          this->auth_table->do_with(userActual, [&] (AuthTableEntry &ae) { //actual storage interaction
            ae.content = contentActual;
          });

      }

      else if (whichCmd.compare(KVDELETE) == 0) {
        std::string key; 

        size_t key_len = *(size_t *)(receivedData.data() + index);
        index += 8;

        key.insert(key.end(), receivedData.begin() + index, receivedData.begin() + index + key_len);

       
        index += key_len; 

        size_t totalSize = 16 + key_len;

        if ((totalSize % 8) > 0) {
          int padding_Amt = 8 - (totalSize % 8);
          index += padding_Amt;
        }

        this->kv_store->remove(key, [](){});
      }

      else if (whichCmd.compare(KVUPDATE) == 0) {
        std::string key; 
        std::vector<uint8_t> val; 

        size_t len_key = *(size_t *)(receivedData.data() + index);
        index += 8;

        key.insert(key.end(), receivedData.begin() + index, receivedData.begin() + index + len_key);
        index += len_key;
        
        size_t val_len = *(size_t *)(receivedData.data() + index);
        index += 8;

        val.insert(val.end(), receivedData.begin() + index, receivedData.begin() + index + val_len);
        index += val_len;

        size_t totalSize = 24 + len_key + val_len;

        if ((totalSize % 8) > 0) {
          size_t padding_Amt = 8 - (totalSize % 8);
          index += padding_Amt;
        }

        this->kv_store->upsert(key, val, [](){}, [](){});
        
      }

      whichCmd.clear();
    } //end of while loop... MAKE SURE INDEX MATCHES...

    return {true, "Loaded: " + filename, {}};
}


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
