#ifndef BROKER_SUBSCRIBER_HH
#define BROKER_SUBSCRIBER_HH

#include <vector>

#include <caf/actor.hpp>

#include "broker/data.hh"
#include "broker/fwd.hh"
#include "broker/topic.hh"
#include "broker/subscriber_base.hh"

#include "broker/detail/shared_subscriber_queue.hh"

namespace broker {

/// Provides blocking access to a stream of data.
class subscriber : public subscriber_base<std::pair<topic, data>> {
public:
  // --- friend declarations ---------------------------------------------------

  friend class endpoint;

  // --- nested types ----------------------------------------------------------

  using super = subscriber_base<std::pair<topic, data>>;

  // --- constructors and destructors ------------------------------------------

  subscriber(subscriber&&) = default;

  subscriber& operator=(subscriber&&) = default;

  ~subscriber();

  size_t rate() const;

  inline const caf::actor& worker() const {
    return worker_;
  }

  void add_topic(topic x, bool block = false);

  void remove_topic(topic x, bool block = false);

  /// Enables or disables rate calculation. On by default.
  void set_rate_calculation(bool x);

protected:
  void became_not_full() override;

private:
  // -- force users to use `endpoint::make_status_subscriber` -------------------
  subscriber(endpoint& ep, std::vector<topic> ts, size_t max_qsize);

  caf::actor worker_;
  std::vector<topic> filter_;
  endpoint& ep_;
};

} // namespace broker

#endif // BROKER_SUBSCRIBER_HH
