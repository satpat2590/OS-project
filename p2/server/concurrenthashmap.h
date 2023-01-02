#include <cassert>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>
#include <stdio.h>
#include <utility>


#include "map.h"

/// ConcurrentHashMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of vecBucket, with one lock
/// per bucket.  Since the number of vecBucket is fixed, performance can suffer if
/// the thread count is high relative to the number of vecBucket.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of vecBucket.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentHashMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @param K The type of the keys in this map
/// @param V The type of the values in this map
template <typename K, typename V> class ConcurrentHashMap : public Map<K, V> {

public:

  typedef struct bucket{
    std::list<std::pair<K, V> > info; 
    std::mutex bucketLock; 
  }bucket; 

  std::vector<bucket *> vecBucket; 
  size_t numBuckets; 

  /// Construct by specifying the number of vecBucket it should have
  ///
  /// @param _vecBucket The number of vecBucket
  ConcurrentHashMap(size_t _vecBucket) : numBuckets(_vecBucket) {
    for (size_t i = 0; i < numBuckets; i++) {
      bucket *newBuck = new bucket; 
      vecBucket.push_back(newBuck);       
    }
  }

  /// Destruct the ConcurrentHashMap
  virtual ~ConcurrentHashMap() { }

  size_t hashing(K key) {
    std::hash<K> hash;
    std::size_t finHash = hash(key);
    size_t buckNum = finHash % numBuckets;
    if (buckNum > numBuckets)
      return -1;

    return buckNum;
  }

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {

    std::vector<std::unique_lock<std::mutex> > lockAll; 
    for (auto &i : vecBucket) {
      lockAll.push_back(std::unique_lock<std::mutex>(i->bucketLock));
    }

    for (auto &i : vecBucket) {
      i->info.clear();
    }



    // for (int i = 0; i < numBuckets; i++) {
    //   (vecBucket.at(i).bucketLock).lock();
    //   // clear what is in the bucket
    //   for (int k = 0; k < vecBucket.at(i).info.size(); k++) {
    //     (vecBucket.at(i).info).pop_back();
    //   }
    // }
    // for (int i = 0; i < numBuckets; i++) {
    //   (vecBucket.at(i).bucketLock).unlock();
    // }
  }



  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val, std::function<void()> on_success) {
    // hash the key
    int hashedKey = hashing(key);

    if (hashedKey == -1) {
      return false;
    }

    auto &bucket = vecBucket[hashedKey];
    std::lock_guard<std::mutex> lock(bucket->bucketLock);
    for (auto &i : bucket->info) {
      if (i.first == key) {
        return false;
      }
    }

    bucket->info.push_back(std::make_pair(key, val)); 
    on_success();
    return true;




  //   //typename std::list<std::pair<K, V> >::iterator it;
  //   for (auto it = (vecBucket.at(hashedKey).info).begin(); it != (vecBucket.at(hashedKey).info).end(); it++) {
  //     if (it->first == key) {
  //       return false; 
  //     }
  //   }

  //   for (size_t i = 0; i < (vecBucket.at(hashedKey).info).size(); i++) {
  //     if (key == (vecBucket.at(hashedKey).info).at(i).first) {
  //       (vecBucket.at(hashedKey).bucketLock).unlock();
  //       return false;
  //     }
  //   }

  //   (vecBucket.at(hashedKey).info).push_back(std::pair<K, V>(key, val));
    
  //   on_success();
  //   return true; 
  // }
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val, std::function<void()> on_ins,
                      std::function<void()> on_upd) {
    int hashedKey = hashing(key);
  
    auto &bucket = vecBucket[hashedKey];
   
    std::lock_guard<std::mutex> lock(bucket->bucketLock);
  
    for (auto &i : bucket->info) {
      if (i.first == key) {
        i.second = val;
        on_upd();
        return false; 
      }
    }

    bucket->info.push_back(std::make_pair(key, val)); 
    on_ins();
    return true;



    // (vecBucket.at(hashedKey).bucketLock).lock();

    // if (hashedKey == -1) {
    //   (vecBucket.at(hashedKey).bucketLock).unlock();
    //   return false;
    // }
    // //typename std::list<std::pair<K, V> >::iterator it;
    // for (auto it = (vecBucket.at(hashedKey).info).begin(); it != (vecBucket.at(hashedKey).info).end(); it++) {
    //   if (it->first == key) {
    //     it->second = val;
    //     on_upd();
    //     ((vecBucket.at(hashedKey).bucketLock)).unlock();
    //     return false;
    //   }
    // }
    
    // (vecBucket.at(hashedKey).info).push_back(std::pair<K, V>(key, val));
    // on_ins();
    // ((vecBucket.at(hashedKey).bucketLock)).unlock();
    // return true;

  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {

    int hashedKey = hashing(key);
    auto &bucket = vecBucket[hashedKey];
    std::lock_guard<std::mutex> lock(bucket->bucketLock);
    for (auto &i : bucket->info) {
      if (i.first == key) {
        f(i.second);
        return true;
      }
    }
    // no key found
    return false;

    // (vecBucket.at(hashedKey).bucketLock).lock();

    // if (hashedKey == -1) {
    //   (vecBucket.at(hashedKey).bucketLock).unlock();
    //   return false;
    // }
    // //typename std::list<std::pair<K, V> >::iterator it;
    // for (auto it = vecBucket.at(hashedKey).info.begin(); it != vecBucket.at(hashedKey).info.end(); it++) {
    //   if (it->first == key) {
    //     f(it->second);
    //     (vecBucket.at(hashedKey).bucketLock).unlock();
    //     return true;
    //   }
    // }
    // (vecBucket.at(hashedKey).bucketLock).unlock();
    // return false; 
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    int hashedKey = hashing(key);

    auto &bucket = vecBucket[hashedKey];
    std::lock_guard<std::mutex> lock(bucket->bucketLock);

    // iterate over info to find the matching key
    for (auto &i : bucket->info) {
      if (i.first == key) {
        f(i.second);
        return true;
      }
    }

    return false;

    // (vecBucket.at(hashedKey).bucketLock).lock();

    // if (hashedKey == -1) {
    //   (vecBucket.at(hashedKey).bucketLock).unlock();
    //   return false;
    // }
    // //const typename std::list<std::pair<K, V> >::iterator it;
    // for (auto it = vecBucket.at(hashedKey).info.cbegin(); it != vecBucket.at(hashedKey).info.cend(); it++) {
    //   if (it->first == key) {
    //     f(it->second);
    //     (vecBucket.at(hashedKey).bucketLock).unlock();
    //     return true;
    //   }
    // }
    // (vecBucket.at(hashedKey).bucketLock).unlock();

    // return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key, std::function<void()> on_success) {
    int hashedKey = hashing(key);

 
    auto &bucket = vecBucket[hashedKey];
  
    std::lock_guard<std::mutex> lock(bucket->bucketLock);

    for (auto i = bucket->info.begin(); i != bucket->info.end(); i++) {
      auto &temp = *i; 
      if (temp.first == key) {
        bucket->info.erase(i); 
        on_success();
        return true;
      }
    }
    return false; // else key was not found

    // (vecBucket.at(hashedKey).bucketLock).lock();

    // if (hashedKey == -1) {
    //   (vecBucket.at(hashedKey).bucketLock).unlock();
    //   return false;
    // }
    // //typename std::list<std::pair<K, V> >::iterator it
    // for (auto it = vecBucket.at(hashedKey).info.begin(); it != vecBucket.at(hashedKey).info.end(); it++) {
    //   if (it->first == key) {
    //     it = vecBucket.at(hashedKey).info.erase(it);
    //     on_success();
    //     (vecBucket.at(hashedKey).bucketLock).unlock();
    //     return true;
    //   }
    // }
    // (vecBucket.at(hashedKey).bucketLock).unlock();
    // return false;
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f, std::function<void()> then) {
    //const typename std::vector<bucket>::iterator itlock;

    // 2PL: phase 1 locks, phase 2 unlocks
    std::vector<std::unique_lock<std::mutex> > lockAll; 
    for (auto &i : vecBucket) {
      lockAll.push_back(std::unique_lock<std::mutex>(i->bucketLock));
    }

    for (auto &i : vecBucket) {
      for (auto &j : i->info) {
        f(j.first, j.second);
      }
    }
    then(); // done applying f but before unlocking




    // for (int i = 0; i < numBuckets; i++) {
    //   (vecBucket.at(numBuckets).bucketLock).lock();
    // } 
    
    // //const typename std::vector<bucket>::iterator it;
    // //const typename std::list<std::pair<K, V> >::iterator iter
    // for (auto it = vecBucket.cbegin(); it != vecBucket.cend(); it++) {
    //   for (auto iter = it->info.cbegin(); iter != it->info.cend(); iter++) {
    //     f(iter->first, iter->second);
    //   }
    // }
    // then();
    // //const typename std::vector<bucket>::iterator itUnlock;
    // for (int i = 0; i < numBuckets; i++) {
    //   (vecBucket.at(numBuckets).bucketLock).unlock();
    // }
  }
};
