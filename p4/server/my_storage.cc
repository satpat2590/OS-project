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

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "persist.h"
#include "quotas.h"
#include "storage.h"

using namespace std;

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

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The table for tracking the most recently used keys
  mru_manager *mru;

  /// A table for tracking quotas
  Map<string, Quotas *> *quota_table;

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
  MyStorage(const std::string &fname, size_t buckets, size_t upq, size_t dnq,
            size_t rqq, double qd, size_t top, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    // TODO: you probably want to free some memory here...

    // thank you for this reminder professor. 

    quota_table->clear(); 
    delete quota_table; 
    kv_store->clear();
    delete kv_store; 
    auth_table->clear(); 
    delete auth_table; 
    mru->clear();
    delete mru;

  }

  /// Check the quota_table->download data structure to see if request is satisfiable 
  /// 
  ///
  /// @param user      The name of the user whose quota is being checked
  /// @param amount    The amount user wishes to download as per one request 
  ///
  /// @return False if the quota is exceeded, true otherwise
  virtual bool download_check(const std::string &user, size_t amount) {
    bool ret = 1;

    quota_table->do_with(user, [&] (Quotas *val) {
      if (!val->downloads->check_add(amount))
        ret = 0; 
    });

    return ret; 
  }

  /// Check the quota_table->uploads data structure to see if request is satisfiable
  ///
  ///
  /// @param user      The name of the user whose quota is being checked
  /// @param amount    The amount the user wishes to upload as per one request
  ///
  /// @return False if the quota is exceeded, true otherwise
  virtual bool upload_check(const std::string &user, size_t amount) {
    bool ret = 1;

    quota_table->do_with(user, [&] (Quotas *val) {
      if (!val->uploads->check_add(amount))
        ret = 0; 
    });

    return ret; 
  }

  /// Check the quota_table->requests data structure to see if request is satisfiable
  ///
  ///
  /// @param user    The name of the user whose quota is being checked
  ///
  /// @return False if the quota is exceeded, true otherwise
  virtual bool req_check(const std::string &user) {
    bool ret = 1;

    quota_table->do_with(user, [&] (Quotas *val) {
      if (!val->requests->check_add(1))
        ret = 0; 
    });

    return ret; 
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
    // NB: the helper (.o provided) does all the work for this operation :)

    // creating a new Quota struct holding download, upload, and request tracking information 

    // hierarchy : Quota.h (struct Quota) -> Quota_tracker -> quota_table holding <string, &Quota>  
    Quotas *newQuota = new Quotas(); 
    newQuota->downloads = quota_factory(down_quota, quota_dur);
    newQuota->uploads = quota_factory(up_quota, quota_dur);
    newQuota->requests = quota_factory(req_quota, quota_dur);

    if (!quota_table->insert(user, newQuota, [] () {}))
      delete newQuota; 

    return add_user_helper(user, pass, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return set_user_data_helper(user, pass, content, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_user_data_helper(user, pass, who, auth_table);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return auth_helper(user, pass, auth_table);
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
    // NB: log_sv() in persist.h (implementation in persist.o) will be helpful
    //     here
    auto authReturn = auth(user, pass); 

    if (!authReturn.succeeded) 
      return result_t{false, RES_ERR_LOGIN, {}};

    if (!req_check(user))
      return result_t{false, RES_ERR_QUOTA_REQ, {}};

    if (!upload_check(user, val.size()))
      return result_t{false, RES_ERR_QUOTA_UP, {}};

    bool check = this->kv_store->insert(key, val, [&] () {
      log_sv(storage_file, KVENTRY, key, val);
    });

    if (check == false) 
      return result_t{false, RES_ERR_USER_EXISTS, {}};
    
    mru->insert(key);
    return result_t{true, RES_OK, {}};
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass, const string &key) {

    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    std::vector<uint8_t> valReturn; 
    
    auto f = [&] (const std::vector<uint8_t> &val) {
      valReturn = val; 
    };

    if (!req_check(user))
      return result_t{false, RES_ERR_QUOTA_REQ, {}};

    bool thisisSparta = this->kv_store->do_with_readonly(key, f);

    if (!download_check(user, valReturn.size()))
      return result_t{false, RES_ERR_QUOTA_DOWN, {}};


    if (!thisisSparta) 
      return result_t{false, RES_ERR_KEY, {}};
    

    if (valReturn.size() != 0) {
      mru->insert(key);
      return result_t{true, RES_OK, {valReturn} };
    }

    return result_t{false, RES_ERR_KEY, {valReturn} };

    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};
    // NB: log_s() in persist.h (implementation in persist.o) will be helpful
    //     here
    if (!req_check(user))
      return result_t{false, RES_ERR_QUOTA_REQ, {}};

    kv_store->remove(key, [&] () { log_s(storage_file, KVDELETE, key); });
    mru->remove(key);

    return result_t{true, RES_OK, {}};

    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    // NB: log_sv() in persist.h (implementation in persist.o) will be helpful
    //     here

    if (!req_check(user))
      return result_t{false, RES_ERR_QUOTA_REQ, {}};

    if (!upload_check(user, val.size()))
      return result_t{false, RES_ERR_QUOTA_UP, {}};

    bool check = kv_store->upsert(key, val, [&] () { log_sv(storage_file, KVUPDATE, key, val); }, 
      [&] () { log_sv(storage_file, KVENTRY, key, val); });  

    mru->insert(key);

    if (!check)
      return result_t{true, RES_OKUPD, {}};
    
    return result_t{true, RES_OKINS, {}};

    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(key.length() > 0);
    assert(val.size() > 0);
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    if (!req_check(user))
      return result_t{false, RES_ERR_QUOTA_REQ, {}};
    

    std::vector<uint8_t> rContent; 

    auto f = [&] (std::string key, const std::vector<uint8_t> &val) {
      rContent.insert(rContent.end(), key.begin(), key.end());
      rContent.push_back('\n');
    };
    auto fthen = [] () {};

    kv_store->do_all_readonly(f, fthen);

    if (!download_check(user, rContent.size()))
      return result_t{false, RES_ERR_QUOTA_DOWN, {}};


    if (rContent.size() != 0) 
      return result_t{true, RES_OK, {rContent} };
    

    return result_t{false, RES_ERR_KEY, {rContent} };

    assert(user.length() > 0);
    assert(pass.length() > 0);
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {

    auto authCheck = auth(user, pass);

    if (!authCheck.succeeded) 
      return result_t{false, RES_ERR_LOGIN, {}};

    if (!req_check(user))
      return result_t{false, RES_ERR_QUOTA_REQ, {}};

    std::string mruRet = mru->get();

    if (!download_check(user, mruRet.size()))
      return result_t{false, RES_ERR_QUOTA_DOWN, {}};


    return result_t{true, RES_OK, std::vector<uint8_t>(mruRet.begin(), mruRet.end()) };

    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    assert(user.length() > 0);
    assert(pass.length() > 0);
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    // NB: Based on how the other methods are implemented in the helper file, we
    //     need this command here:
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    // NB: the helper (.o provided) does all the work for this operation :)
    return save_file_helper(auth_table, kv_store, filename, storage_file);
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    // NB: the helper (.o provided) does all the work from p1/p2/p3 for this
    //     operation.  Depending on how you choose to implement quotas, you may
    //     need to edit this.
    return load_file_helper(auth_table, kv_store, filename, storage_file);
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
