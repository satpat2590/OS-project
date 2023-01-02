// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <iostream>
#include <memory>
#include <time.h> 
#include "quota_tracker.h"

using namespace std;

/// quota_tracker stores time-ordered information about events.  It can count
/// events within a pre-set, fixed time threshold, to decide if a new event can
/// be allowed without violating a quota.
class my_quota_tracker : public quota_tracker {


/*
  Structure for tracking all of the user events 

  Insertion Rules: 
    1. Structure contains pairs for each element
    2. Pairs consist of :
      a. time_t value denoting the time in seconds for the event
      b. size_t value denoting the amount of the new event (either in # of requests OR size of download/upload)
*/
std::deque<std::pair<time_t, size_t> > deckCheck;

size_t maxAmount; 
double maxDuration; 

public:
  /// Construct a tracker that limits usage to quota_amount per quota_duration
  /// seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time over which the service maximum can be spread out
  my_quota_tracker(size_t amount, double duration) : maxAmount(amount), maxDuration(duration) {}

  /// Destruct a quota tracker
  virtual ~my_quota_tracker() {}

  /// Decide if a new event is permitted, and if so, add it.  The attempt is
  /// allowed if it could be added to events, while ensuring that the sum of
  /// amounts for all events within the duration is less than q_amnt.
  ///
  /// @param amount The amount of the new request
  ///
  /// @return false if the amount could not be added without violating the
  ///         quota, true if the amount was added while preserving the quota
  virtual bool check_add(size_t amount) {
    time_t timer; 
    time(&timer);
    size_t cAmount = amount; 

    for (auto it = deckCheck.begin(); it < deckCheck.end(); ++it) {

      if ((*it).first >= (timer - maxDuration)) { // if timer > maxDuration, then we're outside of time scope... 
        cAmount += (*it).second;

        if (cAmount > maxAmount) {
          return false; 
        }

      } else break; 
    }

    deckCheck.push_front(std::make_pair(time(NULL), amount));

    return true; 
}

};

/// Construct a tracker that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time over which the service maximum can be spread out
quota_tracker *quota_factory(size_t amount, double duration) {
  return new my_quota_tracker(amount, duration);
}