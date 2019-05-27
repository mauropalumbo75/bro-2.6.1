#ifndef BROKER_DETAIL_FLARE_ACTOR_HH
#define BROKER_DETAIL_FLARE_ACTOR_HH

#include <chrono>
#include <limits>

#include <caf/blocking_actor.hpp>

#include "broker/detail/flare.hh"

namespace broker {
namespace detail {

class flare_actor;

} // namespace detail
} // namespace broker

namespace caf {
namespace mixin {

template <>
struct is_blocking_requester<broker::detail::flare_actor> : std::true_type { };

} // namespace mixin
} // namespace caf

namespace broker {
namespace detail {

class flare_actor : public caf::blocking_actor {
public:
  flare_actor(caf::actor_config& sys);

  void launch(caf::execution_unit*, bool, bool) override;

  void act() override;

  void await_data() override;

  bool await_data(timeout_type timeout) override;

  void enqueue(caf::mailbox_element_ptr ptr, caf::execution_unit*) override;

  caf::mailbox_element_ptr dequeue() override;

  const char* name() const override;

  int descriptor() const;

private:
  flare flare_;
  bool await_flare_;
};

} // namespace detail
} // namespace broker

#endif // BROKER_DETAIL_FLARE_ACTOR_HH
