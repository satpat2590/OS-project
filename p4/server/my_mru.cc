#include <deque>
#include <iostream>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {

/*
  mru is a data structure which holds all of the recently used keys in a deque format 

  goal of mru in terms of project completion is to generate the proper set of "top keys" which is 
    represented in the std::deque<std::string> structure itself 
*/
std::deque<std::string> mru; 

std::mutex mru_lock;

std::size_t maxElements; 

public:
  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) : maxElements(elements) {}

  /// Destruct the mru_manager
  virtual ~my_mru() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {
    remove(elt); // no duplicates ensured

    std::lock_guard<std::mutex> lock(mru_lock);

    // checking if the size of the deque is greater than the elements passed... 
    if (mru.size() >= maxElements) {
      mru.pop_front();
    }

    mru.push_back(elt);
  }

  

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {

    std::lock_guard<std::mutex> lock(mru_lock);

    for (int i = 0; i < mru.size(); i++) {
      if (mru[i].compare(elt) == 0)
        mru.erase(mru.begin() + i);
    }
  
  }

  /// Clear the mru_manager
  virtual void clear() {
    std::lock_guard<std::mutex> lock(mru_lock);
    mru.clear(); 
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() {

    std::lock_guard<std::mutex> lock(mru_lock);
    std::string mruGet; 

    for (auto it : mru) {
      mruGet.insert(mruGet.begin(), '\n');                 // adding newline delimiter after each entry...
      mruGet.insert(mruGet.begin(), it.begin(), it.end()); // inserting required key 
    }

    return mruGet; 
  }
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { return new my_mru(elements); }