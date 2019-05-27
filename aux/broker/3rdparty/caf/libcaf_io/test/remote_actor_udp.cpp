/******************************************************************************
 *                       ____    _    _____                                   *
 *                      / ___|  / \  |  ___|    C++                           *
 *                     | |     / _ \ | |_       Actor                         *
 *                     | |___ / ___ \|  _|      Framework                     *
 *                      \____/_/   \_|_|                                      *
 *                                                                            *
 * Copyright 2011-2018 Dominik Charousset                                     *
 *                                                                            *
 * Distributed under the terms and conditions of the BSD 3-Clause License or  *
 * (at your option) under the terms and conditions of the Boost Software      *
 * License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.       *
 *                                                                            *
 * If you did not receive a copy of the license files, see                    *
 * http://opensource.org/licenses/BSD-3-Clause and                            *
 * http://www.boost.org/LICENSE_1_0.txt.                                      *
 ******************************************************************************/

#include "caf/config.hpp"

#define CAF_SUITE io_dynamic_remote_actor_udp
#include "caf/test/dsl.hpp"

#include <vector>
#include <sstream>
#include <utility>
#include <algorithm>

#include "caf/all.hpp"
#include "caf/io/all.hpp"

using namespace caf;

namespace {

constexpr char local_host[] = "127.0.0.1";

class config : public actor_system_config {
public:
  config() {
    load<io::middleman>();
    set("middleman.enable-udp", true);
    add_message_type<std::vector<int>>("std::vector<int>");
  }
};

struct fixture {
  // State for the server.
  config server_side_config;
  actor_system server_side;
  io::middleman& server_side_mm;

  // State for the client.
  config client_side_config;
  actor_system client_side;
  io::middleman& client_side_mm;

  fixture()
      : server_side(server_side_config.parse(test::engine::argc(),
                                             test::engine::argv())),
        server_side_mm(server_side.middleman()),
        client_side(client_side_config.parse(test::engine::argc(),
                                             test::engine::argv())),
        client_side_mm(client_side.middleman()) {
    // nop
  }
};

behavior make_pong_behavior() {
  return {
    [](int val) -> int {
      ++val;
      CAF_MESSAGE("pong with " << val);
      return val;
    }
  };
}

behavior make_ping_behavior(event_based_actor* self, const actor& pong) {
  CAF_MESSAGE("ping with " << 0);
  self->send(pong, 0);
  return {
    [=](int val) -> int {
      if (val == 3) {
        CAF_MESSAGE("ping with exit");
        self->send_exit(self->current_sender(),
                        exit_reason::user_shutdown);
        CAF_MESSAGE("ping quits");
        self->quit();
      }
      CAF_MESSAGE("ping with " << val);
      return val;
    }
  };
}

behavior make_sort_behavior() {
  return {
    [](std::vector<int>& vec) -> std::vector<int> {
      CAF_MESSAGE("sorter received: " << deep_to_string(vec));
      std::sort(vec.begin(), vec.end());
      CAF_MESSAGE("sorter sent: " << deep_to_string(vec));
      return std::move(vec);
    }
  };
}

behavior make_sort_requester_behavior(event_based_actor* self,
                                      const actor& sorter) {
  self->send(sorter, std::vector<int>{5, 4, 3, 2, 1});
  return {
    [=](const std::vector<int>& vec) {
      CAF_MESSAGE("sort requester received: " << deep_to_string(vec));
      std::vector<int> expected_vec{1, 2, 3, 4, 5};
      CAF_CHECK_EQUAL(vec, expected_vec);
      self->send_exit(sorter, exit_reason::user_shutdown);
      self->quit();
    }
  };
}

behavior fragile_mirror(event_based_actor* self) {
  return {
    [=](int i) {
      self->quit(exit_reason::user_shutdown);
      return i;
    }
  };
}

behavior linking_actor(event_based_actor* self, const actor& buddy) {
  CAF_MESSAGE("link to mirror and send dummy message");
  self->link_to(buddy);
  self->send(buddy, 42);
  return {
    [](int i) {
      CAF_CHECK_EQUAL(i, 42);
    }
  };
}

} // namespace <anonymous>

CAF_TEST_FIXTURE_SCOPE(dynamic_remote_actor_tests_udp, fixture)

CAF_TEST(identity_semantics_udp) {
  // server side
  auto server = server_side.spawn(make_pong_behavior);
  auto port1 = unbox(server_side_mm.publish_udp(server, 0, local_host));
  auto port2 = unbox(server_side_mm.publish_udp(server, 0, local_host));
  CAF_REQUIRE_NOT_EQUAL(port1, port2);
  auto same_server = unbox(server_side_mm.remote_actor_udp(local_host, port2));
  CAF_REQUIRE_EQUAL(same_server, server);
  CAF_CHECK_EQUAL(same_server->node(), server_side.node());
  auto server1 = unbox(client_side_mm.remote_actor_udp(local_host, port1));
  auto server2 = unbox(client_side_mm.remote_actor_udp(local_host, port2));
  CAF_CHECK_EQUAL(server1, client_side_mm.remote_actor_udp(local_host, port1));
  CAF_CHECK_EQUAL(server2, client_side_mm.remote_actor_udp(local_host, port2));
  anon_send_exit(server, exit_reason::user_shutdown);
}

CAF_TEST(ping_pong_udp) {
  // server side
  auto port = unbox(server_side_mm.publish_udp(
    server_side.spawn(make_pong_behavior), 0, local_host));
  // client side
  auto pong = unbox(client_side_mm.remote_actor_udp(local_host, port));
  client_side.spawn(make_ping_behavior, pong);
}

CAF_TEST(custom_message_type_udp) {
  // server side
  auto port = unbox(server_side_mm.publish_udp(
    server_side.spawn(make_sort_behavior), 0, local_host));
  // client side
  auto sorter = unbox(client_side_mm.remote_actor_udp(local_host, port));
  client_side.spawn(make_sort_requester_behavior, sorter);
}

CAF_TEST(remote_link_udp) {
  // server side
  auto port = unbox(server_side_mm.publish_udp(
    server_side.spawn(fragile_mirror), 0, local_host));
  // client side
  auto mirror = unbox(client_side_mm.remote_actor_udp(local_host, port));
  auto linker = client_side.spawn(linking_actor, mirror);
  scoped_actor self{client_side};
  self->wait_for(linker);
  CAF_MESSAGE("linker exited");
  self->wait_for(mirror);
  CAF_MESSAGE("mirror exited");
}

CAF_TEST_DISABLED(multiple_endpoints_udp) {
  config cfg;
  // Setup server.
  CAF_MESSAGE("creating server");
  actor_system server_sys{cfg};
  auto mirror = server_sys.spawn([]() -> behavior {
    return {
      [] (std::string str) {
        std::reverse(begin(str), end(str));
        return str;
      }
    };
  });
  auto port = server_sys.middleman().publish_udp(mirror, 0);
  CAF_REQUIRE(port);
  CAF_MESSAGE("server running on port " << port);
  auto client_fun = [](event_based_actor* self) -> behavior {
    return {
      [=](actor s) {
        self->send(s, "hellow, world");
      },
      [=](const std::string& str) {
        CAF_CHECK_EQUAL(str, "dlrow ,wolleh");
        self->quit();
        CAF_MESSAGE("done");
      }
    };
  };
  // Setup a client.
  CAF_MESSAGE("creating first client");
  config client_cfg;
  actor_system client_sys{client_cfg};
  auto client = client_sys.spawn(client_fun);
  // Acquire remote actor from the server.
  auto client_srv = client_sys.middleman().remote_actor_udp("localhost", *port);
  CAF_REQUIRE(client_srv);
  // Setup other clients.
  for (int i = 0; i < 5; ++i) {
    config other_cfg;
    actor_system other_sys{other_cfg};
    CAF_MESSAGE("creating new client");
    auto other = other_sys.spawn(client_fun);
    // Acquire remote actor from the new server.
    auto other_srv = other_sys.middleman().remote_actor_udp("localhost", *port);
    CAF_REQUIRE(other_srv);
    // Establish communication and exit.
    CAF_MESSAGE("client contacts server and exits");
    anon_send(other, *other_srv);
    other_sys.await_all_actors_done();
  }
  // Start communicate from the first actor.
  CAF_MESSAGE("first client contacts server and exits");
  anon_send(client, *client_srv);
  client_sys.await_all_actors_done();
  anon_send_exit(mirror, exit_reason::user_shutdown);
}

CAF_TEST_FIXTURE_SCOPE_END()
