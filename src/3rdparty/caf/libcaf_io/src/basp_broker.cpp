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

#include "caf/io/basp_broker.hpp"

#include <chrono>
#include <limits>

#include "caf/actor_registry.hpp"
#include "caf/actor_system_config.hpp"
#include "caf/after.hpp"
#include "caf/defaults.hpp"
#include "caf/detail/sync_request_bouncer.hpp"
#include "caf/event_based_actor.hpp"
#include "caf/forwarding_actor_proxy.hpp"
#include "caf/io/basp/all.hpp"
#include "caf/io/connection_helper.hpp"
#include "caf/io/middleman.hpp"
#include "caf/io/network/interfaces.hpp"
#include "caf/make_counted.hpp"
#include "caf/sec.hpp"
#include "caf/send.hpp"

namespace caf {
namespace io {

namespace {

// visitors to access handle variant of the context
struct seq_num_visitor {
  using result_type = basp::sequence_type;
  seq_num_visitor(basp_broker_state* ptr) : state(ptr) { }
  template <class T>
  result_type operator()(const T& hdl) {
    return state->next_sequence_number(hdl);
  }
  basp_broker_state* state;
};

struct close_visitor {
  using result_type = void;
  close_visitor(broker* ptr) : b(ptr) { }
  template <class T>
  result_type operator()(const T& hdl) {
    b->close(hdl);
  }
  broker* b;
};

} // namespace anonymous

const char* basp_broker_state::name = "basp_broker";

/******************************************************************************
 *                             basp_broker_state                              *
 ******************************************************************************/

basp_broker_state::basp_broker_state(broker* selfptr)
    : basp::instance::callee(selfptr->system(),
                             static_cast<proxy_registry::backend&>(*this)),
      self(selfptr),
      instance(selfptr, *this),
      max_buffers(get_or(self->config(), "middleman.cached-udp-buffers",
                         defaults::middleman::cached_udp_buffers)),
      max_pending_messages(get_or(self->config(), "middleman.max-pending-msgs",
                                  defaults::middleman::max_pending_msgs)) {
  CAF_ASSERT(this_node() != none);
}

basp_broker_state::~basp_broker_state() {
  // make sure all spawn servers are down
  for (auto& kvp : spawn_servers)
    anon_send_exit(kvp.second, exit_reason::kill);
}

strong_actor_ptr basp_broker_state::make_proxy(node_id nid, actor_id aid) {
  CAF_LOG_TRACE(CAF_ARG(nid) << CAF_ARG(aid));
  CAF_ASSERT(nid != this_node());
  if (nid == none || aid == invalid_actor_id)
    return nullptr;
  // this member function is being called whenever we deserialize a
  // payload received from a remote node; if a remote node A sends
  // us a handle to a third node B, then we assume that A offers a route to B
  if (nid != this_context->id
      && !instance.tbl().lookup_direct(nid)
      && instance.tbl().add_indirect(this_context->id, nid))
    learned_new_node_indirectly(nid);
  // we need to tell remote side we are watching this actor now;
  // use a direct route if possible, i.e., when talking to a third node
  auto path = instance.tbl().lookup(nid);
  if (!path) {
    // this happens if and only if we don't have a path to `nid`
    // and current_context_->hdl has been blacklisted
    CAF_LOG_DEBUG("cannot create a proxy instance for an actor "
                  "running on a node we don't have a route to");
    return nullptr;
  }
  // create proxy and add functor that will be called if we
  // receive a kill_proxy_instance message
  auto mm = &system().middleman();
  actor_config cfg;
  auto res = make_actor<forwarding_actor_proxy, strong_actor_ptr>(
    aid, nid, &(self->home_system()), cfg, self);
  strong_actor_ptr selfptr{self->ctrl()};
  res->get()->attach_functor([=](const error& rsn) {
    mm->backend().post([=] {
      // using res->id() instead of aid keeps this actor instance alive
      // until the original instance terminates, thus preventing subtle
      // bugs with attachables
      auto bptr = static_cast<basp_broker*>(selfptr->get());
      if (!bptr->getf(abstract_actor::is_terminated_flag))
        bptr->state.proxies().erase(nid, res->id(), rsn);
    });
  });
  CAF_LOG_DEBUG("successfully created proxy instance, "
                "write announce_proxy_instance:"
                << CAF_ARG(nid) << CAF_ARG(aid));
  auto& ctx = *this_context;
  // tell remote side we are monitoring this actor now
  instance.write_announce_proxy(self->context(),
                                get_buffer(this_context->hdl),
                                nid, aid,
                                ctx.requires_ordering ? ctx.seq_outgoing++ : 0);
  instance.flush(*path);
  mm->notify<hook::new_remote_actor>(res);
  return res;
}

execution_unit* basp_broker_state::registry_context() {
  return self->context();
}

void basp_broker_state::finalize_handshake(const node_id& nid, actor_id aid,
                                           std::set<std::string>& sigs) {
  CAF_LOG_TRACE(CAF_ARG(nid) << CAF_ARG(aid) << CAF_ARG(sigs));
  CAF_ASSERT(this_context != nullptr);
  this_context->id = nid;
  auto& cb = this_context->callback;
  if (cb == none)
    return;
  strong_actor_ptr ptr;
  // aid can be invalid when connecting to the default port of a node
  if (aid != invalid_actor_id) {
    if (nid == this_node()) {
      // connected to self
      ptr = actor_cast<strong_actor_ptr>(system().registry().get(aid));
      CAF_LOG_DEBUG_IF(!ptr, "actor not found:" << CAF_ARG(aid));
    } else {
      ptr = namespace_.get_or_put(nid, aid);
      CAF_LOG_ERROR_IF(!ptr, "creating actor in finalize_handshake failed");
    }
  }
  cb->deliver(nid, std::move(ptr), std::move(sigs));
  cb = none;
}

void basp_broker_state::purge_state(const node_id& nid) {
  CAF_LOG_TRACE(CAF_ARG(nid));
  // Destroy all proxies of the lost node.
  namespace_.erase(nid);
  // Cleanup all remaining references to the lost node.
  for (auto& kvp : monitored_actors)
    kvp.second.erase(nid);
}

void basp_broker_state::send_kill_proxy_instance(const node_id& nid,
                                                 actor_id aid, error rsn) {
  CAF_LOG_TRACE(CAF_ARG(nid) << CAF_ARG(aid) << CAF_ARG(rsn));
  auto path = instance.tbl().lookup(nid);
  if (!path) {
    CAF_LOG_INFO("cannot send exit message for proxy, no route to host:"
                 << CAF_ARG(nid));
    return;
  }
  instance.write_kill_proxy(self->context(),
                            get_buffer(path->hdl),
                            nid, aid, rsn,
                            visit(seq_num_visitor{this}, path->hdl));
  instance.flush(*path);
}

void basp_broker_state::proxy_announced(const node_id& nid, actor_id aid) {
  CAF_LOG_TRACE(CAF_ARG(nid) << CAF_ARG(aid));
  // source node has created a proxy for one of our actors
  auto ptr = system().registry().get(aid);
  if (ptr == nullptr) {
    CAF_LOG_DEBUG("kill proxy immediately");
    // kill immediately if actor has already terminated
    send_kill_proxy_instance(nid, aid, exit_reason::unknown);
  } else {
    auto entry = ptr->address();
    auto i = monitored_actors.find(entry);
    if (i == monitored_actors.end()) {
      self->monitor(ptr);
      std::unordered_set<node_id> tmp{nid};
      monitored_actors.emplace(entry, std::move(tmp));
    } else {
      i->second.emplace(nid);
    }
  }
}

void basp_broker_state::handle_down_msg(down_msg& dm) {
  auto i = monitored_actors.find(dm.source);
  if (i == monitored_actors.end())
    return;
  for (auto& nid : i->second)
    send_kill_proxy_instance(nid, dm.source.id(), dm.reason);
  monitored_actors.erase(i);
}

void basp_broker_state::deliver(const node_id& src_nid, actor_id src_aid,
                                actor_id dest_aid, message_id mid,
                                std::vector<strong_actor_ptr>& stages,
                                message& msg) {
  CAF_LOG_TRACE(CAF_ARG(src_nid) << CAF_ARG(src_aid)
                << CAF_ARG(dest_aid) << CAF_ARG(msg) << CAF_ARG(mid));
  deliver(src_nid, src_aid, system().registry().get(dest_aid),
          mid, stages, msg);
}

void basp_broker_state::deliver(const node_id& src_nid, actor_id src_aid,
                                atom_value dest_name, message_id mid,
                                std::vector<strong_actor_ptr>& stages,
                                message& msg) {
  CAF_LOG_TRACE(CAF_ARG(src_nid) << CAF_ARG(src_aid)
                << CAF_ARG(dest_name) << CAF_ARG(msg) << CAF_ARG(mid));
  deliver(src_nid, src_aid, system().registry().get(dest_name),
          mid, stages, msg);
}

void basp_broker_state::deliver(const node_id& src_nid, actor_id src_aid,
                                strong_actor_ptr dest, message_id mid,
                                std::vector<strong_actor_ptr>& stages,
                                message& msg) {
  CAF_LOG_TRACE(CAF_ARG(src_nid) << CAF_ARG(src_aid) << CAF_ARG(dest)
                << CAF_ARG(msg) << CAF_ARG(mid));
  auto src = src_nid == this_node() ? system().registry().get(src_aid)
                                    : proxies().get_or_put(src_nid, src_aid);
  // Intercept link messages. Forwarding actor proxies signalize linking
  // by sending link_atom/unlink_atom message with src = dest.
  if (msg.type_token() == make_type_token<atom_value, strong_actor_ptr>()) {
    switch (static_cast<uint64_t>(msg.get_as<atom_value>(0))) {
      default:
        break;
      case link_atom::value.uint_value(): {
        if (src_nid != this_node()) {
          CAF_LOG_WARNING("received link message for another node");
          return;
        }
        auto ptr = msg.get_as<strong_actor_ptr>(1);
        if (!ptr) {
          CAF_LOG_WARNING("received link message with invalid target");
          return;
        }
        if (!src) {
          CAF_LOG_DEBUG("received link for invalid actor, report error");
          anon_send(actor_cast<actor>(ptr),
                    make_error(sec::remote_linking_failed));
          return;
        }
        static_cast<actor_proxy*>(ptr->get())->add_link(src->get());
        return;
      }
      case unlink_atom::value.uint_value(): {
        if (src_nid != this_node()) {
          CAF_LOG_WARNING("received unlink message for an other node");
          return;
        }
        const auto& ptr = msg.get_as<strong_actor_ptr>(1);
        if (!ptr) {
          CAF_LOG_DEBUG("received unlink message with invalid target");
          return;
        }
        if (!src) {
          CAF_LOG_DEBUG("received unlink for invalid actor, report error");
          return;
        }
        static_cast<actor_proxy*>(ptr->get())->remove_link(src->get());
        return;
      }
    }
  }
  if (!dest) {
    auto rsn = exit_reason::remote_link_unreachable;
    CAF_LOG_INFO("cannot deliver message, destination not found");
    self->parent().notify<hook::invalid_message_received>(src_nid, src,
                                                          invalid_actor_id,
                                                          mid, msg);
    if (mid.valid() && src) {
      detail::sync_request_bouncer srb{rsn};
      srb(src, mid);
    }
    return;
  }
  self->parent().notify<hook::message_received>(src_nid, src, dest, mid, msg);
  dest->enqueue(make_mailbox_element(std::move(src), mid, std::move(stages),
                                     std::move(msg)),
                nullptr);
}

void basp_broker_state::learned_new_node(const node_id& nid) {
  CAF_LOG_TRACE(CAF_ARG(nid));
  if (spawn_servers.count(nid) > 0) {
    CAF_LOG_ERROR("learned_new_node called for known node " << CAF_ARG(nid));
    return;
  }
  auto tmp = system().spawn<hidden>([=](event_based_actor* tself) -> behavior {
    CAF_LOG_TRACE("");
    // terminate when receiving a down message
    tself->set_down_handler([=](down_msg& dm) {
      CAF_LOG_TRACE(CAF_ARG(dm));
      tself->quit(std::move(dm.reason));
    });
    // skip messages until we receive the initial ok_atom
    tself->set_default_handler(skip);
    return {
      [=](ok_atom, const std::string& /* key == "info" */,
          const strong_actor_ptr& config_serv, const std::string& /* name */) {
        CAF_LOG_TRACE(CAF_ARG(config_serv));
        // drop unexpected messages from this point on
        tself->set_default_handler(print_and_drop);
        if (!config_serv)
          return;
        tself->monitor(config_serv);
        tself->become(
          [=](spawn_atom, std::string& type, message& args)
          -> delegated<strong_actor_ptr, std::set<std::string>> {
            CAF_LOG_TRACE(CAF_ARG(type) << CAF_ARG(args));
            tself->delegate(actor_cast<actor>(std::move(config_serv)),
                            get_atom::value, std::move(type),
                            std::move(args));
            return {};
          }
        );
      },
      after(std::chrono::minutes(5)) >> [=] {
        CAF_LOG_INFO("no spawn server found:" << CAF_ARG(nid));
        tself->quit();
      }
    };
  });
  spawn_servers.emplace(nid, tmp);
  using namespace detail;
  system().registry().put(tmp.id(), actor_cast<strong_actor_ptr>(tmp));
  auto writer = make_callback([](serializer& sink) -> error {
    auto name_atm = atom("SpawnServ");
    std::vector<actor_id> stages;
    auto msg = make_message(sys_atom::value, get_atom::value, "info");
    return sink(name_atm, stages, msg);
  });
  auto path = instance.tbl().lookup(nid);
  if (!path) {
    CAF_LOG_ERROR("learned_new_node called, but no route to nid");
    return;
  }
  // send message to SpawnServ of remote node
  basp::header hdr{basp::message_type::dispatch_message,
                   basp::header::named_receiver_flag,
                   0, 0, this_node(), nid, tmp.id(), invalid_actor_id,
                   visit(seq_num_visitor{this}, path->hdl)};
  // writing std::numeric_limits<actor_id>::max() is a hack to get
  // this send-to-named-actor feature working with older CAF releases
  instance.write(self->context(), get_buffer(path->hdl),
                 hdr, &writer);
  instance.flush(*path);
}

void basp_broker_state::learned_new_node_directly(const node_id& nid,
                                                  bool was_indirectly_before) {
  CAF_ASSERT(this_context != nullptr);
  CAF_LOG_TRACE(CAF_ARG(nid));
  if (!was_indirectly_before)
    learned_new_node(nid);
}

void basp_broker_state::learned_new_node_indirectly(const node_id& nid) {
  CAF_ASSERT(this_context != nullptr);
  CAF_LOG_TRACE(CAF_ARG(nid));
  learned_new_node(nid);
  if (!automatic_connections)
    return;
  // this member function gets only called once, after adding a new
  // indirect connection to the routing table; hence, spawning
  // our helper here exactly once and there is no need to track
  // in-flight connection requests
  auto path = instance.tbl().lookup(nid);
  if (!path) {
    CAF_LOG_ERROR("learned_new_node_indirectly called, but no route to nid");
    return;
  }
  if (path->next_hop == nid) {
    CAF_LOG_ERROR("learned_new_node_indirectly called with direct connection");
    return;
  }
  using namespace detail;
  auto try_connect = [&](std::string item) {
    auto tmp = get_or(config(), "middleman.attach-utility-actors", false)
               ? system().spawn<hidden>(connection_helper, self)
               : system().spawn<detached + hidden>(connection_helper, self);
    system().registry().put(tmp.id(), actor_cast<strong_actor_ptr>(tmp));
    auto writer = make_callback([&item](serializer& sink) -> error {
      auto name_atm = atom("ConfigServ");
      std::vector<actor_id> stages;
      auto msg = make_message(get_atom::value, std::move(item));
      return sink(name_atm, stages, msg);
    });
    basp::header hdr{basp::message_type::dispatch_message,
                     basp::header::named_receiver_flag,
                     0, 0, this_node(), nid, tmp.id(), invalid_actor_id,
                     visit(seq_num_visitor{this}, path->hdl)};
    instance.write(self->context(), get_buffer(path->hdl),
                   hdr, &writer);
    instance.flush(*path);
  };
  if (allow_tcp)
    try_connect("basp.default-connectivity-tcp");
  if (allow_udp)
    try_connect("basp.default-connectivity-udp");
}

void basp_broker_state::set_context(connection_handle hdl) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  auto i = ctx_tcp.find(hdl);
  if (i == ctx_tcp.end()) {
    CAF_LOG_DEBUG("create new BASP context:" << CAF_ARG(hdl));
    i = ctx_tcp.emplace(
      hdl,
      basp::endpoint_context{
        basp::await_header,
        basp::header{basp::message_type::server_handshake, 0,
                     0, 0, none, none,
                     invalid_actor_id, invalid_actor_id},
        hdl, none, 0, 0, none, false, 0, 0,
        basp::endpoint_context::pending_map(), false
      }
    ).first;
  }
  this_context = &i->second;
}

void basp_broker_state::set_context(datagram_handle hdl) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  auto i = ctx_udp.find(hdl);
  if (i == ctx_udp.end()) {
    CAF_LOG_DEBUG("create new BASP context:" << CAF_ARG(hdl));
    i = ctx_udp.emplace(
      hdl,
      basp::endpoint_context{
        basp::await_header,
        basp::header{basp::message_type::server_handshake,
                     0, 0, 0, none, none,
                     invalid_actor_id, invalid_actor_id},
        hdl, none, 0, 0, none, true, 0, 0,
        basp::endpoint_context::pending_map(), false
      }
    ).first;
  }
  this_context = &i->second;
}

void basp_broker_state::cleanup(connection_handle hdl) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  // Remove handle from the routing table and clean up any node-specific state
  // we might still have.
  auto cb = make_callback([&](const node_id& nid) -> error {
    purge_state(nid);
    return none;
  });
  instance.tbl().erase_direct(hdl, cb);
  // Remove the context for `hdl`, making sure clients receive an error in case
  // this connection was closed during handshake.
  auto i = ctx_tcp.find(hdl);
  if (i != ctx_tcp.end()) {
    auto& ref = i->second;
    CAF_ASSERT(i->first == get<connection_handle>(ref.hdl));
    if (ref.callback) {
      CAF_LOG_DEBUG("connection closed during handshake");
      ref.callback->deliver(sec::disconnect_during_handshake);
    }
    ctx_tcp.erase(i);
  }
}

void basp_broker_state::cleanup(datagram_handle hdl) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  // Remove handle from the routing table and clean up any node-specific state
  // we might still have.
  auto cb = make_callback([&](const node_id& nid) -> error {
    purge_state(nid);
    return none;
  });
  instance.tbl().erase_direct(hdl, cb);
  // Remove the context for `hdl`, making sure clients receive an error in case
  // this connection was closed during handshake.
  auto i = ctx_udp.find(hdl);
  if (i != ctx_udp.end()) {
    auto& ref = i->second;
    CAF_ASSERT(i->first == get<datagram_handle>(ref.hdl));
    if (ref.callback) {
      CAF_LOG_DEBUG("connection closed during handshake");
      ref.callback->deliver(sec::disconnect_during_handshake);
    }
    ctx_udp.erase(i);
  }
}

basp::sequence_type basp_broker_state::next_sequence_number(connection_handle) {
  return 0;
}

basp::sequence_type
basp_broker_state::next_sequence_number(datagram_handle hdl) {
  auto i = ctx_udp.find(hdl);
  if (i != ctx_udp.end() && i->second.requires_ordering)
    return i->second.seq_outgoing++;
  return 0;
}

void basp_broker_state::add_pending(execution_unit* ctx,
                                    basp::endpoint_context& ep,
                                    basp::sequence_type seq,
                                    basp::header hdr,
                                    std::vector<char> payload) {
  if (!ep.requires_ordering)
    return;
  ep.pending.emplace(seq, std::make_pair(std::move(hdr), std::move(payload)));
  if (ep.pending.size() >= max_pending_messages)
    deliver_pending(ctx, ep, true);
  else if (!ep.did_set_timeout)
    self->delayed_send(self, pending_to, pending_atom::value,
                       get<datagram_handle>(ep.hdl));
}

bool basp_broker_state::deliver_pending(execution_unit* ctx,
                                        basp::endpoint_context& ep,
                                        bool force) {
  if (!ep.requires_ordering || ep.pending.empty())
    return true;
  std::vector<char>* payload = nullptr;
  auto i = ep.pending.begin();
  // Force delivery of at least the first messages, if desired.
  if (force)
    ep.seq_incoming = i->first;
  while (i != ep.pending.end() && i->first == ep.seq_incoming) {
    ep.hdr = std::move(i->second.first);
    payload = &i->second.second;
    if (!instance.handle(ctx, get<datagram_handle>(ep.hdl),
                         ep.hdr, payload, false, ep, none))
      return false;
    i = ep.pending.erase(i);
    ep.seq_incoming += 1;
  }
  // Set a timeout if there are still pending messages.
  if (!ep.pending.empty() && !ep.did_set_timeout)
    self->delayed_send(self, pending_to, pending_atom::value,
                       get<datagram_handle>(ep.hdl));
  return true;
}

void basp_broker_state::drop_pending(basp::endpoint_context& ep,
                                     basp::sequence_type seq) {
  if (!ep.requires_ordering)
    return;
  ep.pending.erase(seq);
}

basp_broker_state::buffer_type&
basp_broker_state::get_buffer(endpoint_handle hdl) {
  if (hdl.is<connection_handle>())
    return get_buffer(get<connection_handle>(hdl));
  else
    return get_buffer(get<datagram_handle>(hdl));
}

basp_broker_state::buffer_type&
basp_broker_state::get_buffer(datagram_handle) {
  if (cached_buffers.empty())
    cached_buffers.emplace();
  return cached_buffers.top();
}

basp_broker_state::buffer_type&
basp_broker_state::get_buffer(connection_handle hdl) {
  return self->wr_buf(hdl);
}

basp_broker_state::buffer_type
basp_broker_state::pop_datagram_buffer(datagram_handle) {
  std::vector<char> res;
  std::swap(res, cached_buffers.top());
  cached_buffers.pop();
  return res;
}

void basp_broker_state::flush(endpoint_handle hdl) {
  if (hdl.is<connection_handle>())
    flush(get<connection_handle>(hdl));
  else
    flush(get<datagram_handle>(hdl));
}

void basp_broker_state::flush(datagram_handle hdl) {
  if (!cached_buffers.empty() && !cached_buffers.top().empty())
    self->enqueue_datagram(hdl, pop_datagram_buffer(hdl));
  self->flush(hdl);
}

void basp_broker_state::flush(connection_handle hdl) {
  self->flush(hdl);
}

/******************************************************************************
 *                                basp_broker                                 *
 ******************************************************************************/

basp_broker::basp_broker(actor_config& cfg)
    : stateful_actor<basp_broker_state, broker>(cfg) {
  set_down_handler([](local_actor* ptr, down_msg& x) {
    static_cast<basp_broker*>(ptr)->state.handle_down_msg(x);
  });
}

behavior basp_broker::make_behavior() {
  CAF_LOG_TRACE(CAF_ARG(system().node()));
  state.allow_tcp = !get_or(config(), "middleman.disable-tcp", false);
  state.allow_udp = get_or(config(), "middleman.enable-udp", false);
  if (get_or(config(), "middleman.enable-automatic-connections", false)) {
    CAF_LOG_DEBUG("enable automatic connections");
    // open a random port and store a record for our peers how to
    // connect to this broker directly in the configuration server
    if (state.allow_tcp) {
      auto res = add_tcp_doorman(uint16_t{0});
      if (res) {
        auto port = res->second;
        auto addrs = network::interfaces::list_addresses(false);
        auto config_server = system().registry().get(atom("ConfigServ"));
        send(actor_cast<actor>(config_server), put_atom::value,
             "basp.default-connectivity-tcp",
             make_message(port, std::move(addrs)));
      }
    }
    if (state.allow_udp) {
      auto res = add_udp_datagram_servant(uint16_t{0});
      if (res) {
        auto port = res->second;
        auto addrs = network::interfaces::list_addresses(false);
        auto config_server = system().registry().get(atom("ConfigServ"));
        send(actor_cast<actor>(config_server), put_atom::value,
              "basp.default-connectivity-udp",
              make_message(port, std::move(addrs)));
      }
    }
    state.automatic_connections = true;
  }
  auto heartbeat_interval = get_or(config(), "middleman.heartbeat-interval",
                                   defaults::middleman::heartbeat_interval);
  if (heartbeat_interval > 0) {
    CAF_LOG_DEBUG("enable heartbeat" << CAF_ARG(heartbeat_interval));
    send(this, tick_atom::value, heartbeat_interval);
  }
  return {
    // received from underlying broker implementation
    [=](new_data_msg& msg) {
      CAF_LOG_TRACE(CAF_ARG(msg.handle));
      state.set_context(msg.handle);
      auto& ctx = *state.this_context;
      auto next = state.instance.handle(context(), msg, ctx.hdr,
                                        ctx.cstate == basp::await_payload);
      if (next == basp::close_connection) {
        state.cleanup(msg.handle);
        close(msg.handle);
        return;
      }
      if (next != ctx.cstate) {
        auto rd_size = next == basp::await_payload
                       ? ctx.hdr.payload_len
                       : basp::header_size;
        configure_read(msg.handle, receive_policy::exactly(rd_size));
        ctx.cstate = next;
      }
    },
    // received from auto connect broker for UDP communication
    [=](new_datagram_msg& msg, datagram_servant_ptr ptr, uint16_t port) {
      CAF_LOG_TRACE(CAF_ARG(msg.handle));
      auto hdl = ptr->hdl();
      move_datagram_servant(ptr);
      auto& ctx = state.ctx_udp[hdl];
      ctx.hdl = hdl;
      ctx.remote_port = port;
      ctx.local_port = local_port(hdl);
      ctx.requires_ordering = true;
      ctx.seq_incoming = 0;
      ctx.seq_outgoing = 1; // already sent the client handshake
      // Let's not implement this twice
      send(this, std::move(msg));
    },
    // received from underlying broker implementation
    [=](new_datagram_msg& msg) {
      CAF_LOG_TRACE(CAF_ARG(msg.handle));
      state.set_context(msg.handle);
      auto& ctx = *state.this_context;
      if (ctx.local_port == 0)
        ctx.local_port = local_port(msg.handle);
      if (!state.instance.handle(context(), msg, ctx)) {
        if (ctx.callback) {
          CAF_LOG_WARNING("failed to handshake with remote node"
                          << CAF_ARG(msg.handle));
          ctx.callback->deliver(make_error(sec::disconnect_during_handshake));
        }
        state.cleanup(msg.handle);
        close(msg.handle);
      }
    },
    // received from the underlying broker implementation
    [=](datagram_sent_msg& msg) {
      if (state.cached_buffers.size() < state.max_buffers)
        state.cached_buffers.emplace(std::move(msg.buf));
    },
    // received from proxy instances
    [=](forward_atom, strong_actor_ptr& src,
        const std::vector<strong_actor_ptr>& fwd_stack,
        strong_actor_ptr& dest, message_id mid, const message& msg) {
      CAF_LOG_TRACE(CAF_ARG(src) << CAF_ARG(dest)
                    << CAF_ARG(mid) << CAF_ARG(msg));
      if (!dest || system().node() == dest->node()) {
        CAF_LOG_WARNING("cannot forward to invalid or local actor:"
                        << CAF_ARG(dest));
        return;
      }
      if (src && system().node() == src->node())
        system().registry().put(src->id(), src);
      if (!state.instance.dispatch(context(), src, fwd_stack,
                                   dest, mid, msg)
          && mid.is_request()) {
        detail::sync_request_bouncer srb{exit_reason::remote_link_unreachable};
        srb(src, mid);
      }
    },
    // received from some system calls like whereis
    [=](forward_atom, const node_id& dest_node, atom_value dest_name,
        const message& msg) -> result<message> {
      auto cme = current_mailbox_element();
      if (cme == nullptr)
        return sec::invalid_argument;
      auto& src = cme->sender;
      CAF_LOG_TRACE(CAF_ARG(src)
                    << ", " << CAF_ARG(dest_node)
                    << ", " << CAF_ARG(dest_name)
                    << ", " << CAF_ARG(msg));
      if (!src)
        return sec::invalid_argument;
      auto path = this->state.instance.tbl().lookup(dest_node);
      if (!path) {
        CAF_LOG_ERROR("no route to receiving node");
        return sec::no_route_to_receiving_node;
      }
      if (system().node() == src->node())
        system().registry().put(src->id(), src);
      auto writer = make_callback([&](serializer& sink) -> error {
        return sink(dest_name, cme->stages, const_cast<message&>(msg));
      });
      basp::header hdr{basp::message_type::dispatch_message,
                       basp::header::named_receiver_flag,
                       0, cme->mid.integer_value(), state.this_node(),
                       dest_node, src->id(), invalid_actor_id,
                       visit(seq_num_visitor{&state}, path->hdl)};
      state.instance.write(context(), state.get_buffer(path->hdl),
                           hdr, &writer);
      state.instance.flush(*path);
      return delegated<message>();
    },
    // received from underlying broker implementation
    [=](const new_connection_msg& msg) {
      CAF_LOG_TRACE(CAF_ARG(msg.handle));
      auto& bi = state.instance;
      bi.write_server_handshake(context(), state.get_buffer(msg.handle),
                                local_port(msg.source));
      state.flush(msg.handle);
      configure_read(msg.handle, receive_policy::exactly(basp::header_size));
    },
    // received from underlying broker implementation
    [=](const connection_closed_msg& msg) {
      CAF_LOG_TRACE(CAF_ARG(msg.handle));
      state.cleanup(msg.handle);
    },
    // received from underlying broker implementation
    [=](const acceptor_closed_msg& msg) {
      CAF_LOG_TRACE("");
      auto port = local_port(msg.handle);
      state.instance.remove_published_actor(port);
    },
    // received from middleman actor
    [=](publish_atom, doorman_ptr& ptr, uint16_t port,
        const strong_actor_ptr& whom, std::set<std::string>& sigs) {
      CAF_LOG_TRACE(CAF_ARG(ptr) << CAF_ARG(port)
                    << CAF_ARG(whom) << CAF_ARG(sigs));
      CAF_ASSERT(ptr != nullptr);
      add_doorman(std::move(ptr));
      if (whom)
        system().registry().put(whom->id(), whom);
      state.instance.add_published_actor(port, whom, std::move(sigs));
    },
    // received from middleman actor (delegated)
    [=](connect_atom, scribe_ptr& ptr, uint16_t port) {
      CAF_LOG_TRACE(CAF_ARG(ptr) << CAF_ARG(port));
      CAF_ASSERT(ptr != nullptr);
      auto rp = make_response_promise();
      auto hdl = ptr->hdl();
      add_scribe(std::move(ptr));
      auto& ctx = state.ctx_tcp[hdl];
      ctx.hdl = hdl;
      ctx.remote_port = port;
      ctx.cstate = basp::await_header;
      ctx.callback = rp;
      ctx.requires_ordering = false;
      // await server handshake
      configure_read(hdl, receive_policy::exactly(basp::header_size));
    },
    [=](publish_udp_atom, datagram_servant_ptr& ptr, uint16_t port,
        const strong_actor_ptr& whom, std::set<std::string>& sigs) {
      CAF_LOG_TRACE(CAF_ARG(ptr) << CAF_ARG(port)
                    << CAF_ARG(whom) << CAF_ARG(sigs));
      CAF_ASSERT(ptr != nullptr);
      add_datagram_servant(std::move(ptr));
      if (whom)
        system().registry().put(whom->id(), whom);
      state.instance.add_published_actor(port, whom, std::move(sigs));
    },
    // received from middleman actor (delegated)
    [=](contact_atom, datagram_servant_ptr& ptr, uint16_t port) {
      CAF_LOG_TRACE(CAF_ARG(ptr) << CAF_ARG(port));
      auto rp = make_response_promise();
      auto hdl = ptr->hdl();
      add_datagram_servant(std::move(ptr));
      auto& ctx = state.ctx_udp[hdl];
      ctx.hdl = hdl;
      ctx.remote_port = port;
      ctx.local_port = local_port(hdl);
      ctx.callback = rp;
      ctx.requires_ordering = true;
      ctx.seq_incoming = 0;
      ctx.seq_outgoing = 0;
      auto& bi = state.instance;
      bi.write_client_handshake(context(), state.get_buffer(hdl),
                                none, ctx.seq_outgoing++);
      state.flush(hdl);
    },
    // received from underlying broker implementation
    [=](const datagram_servant_closed_msg& msg) {
      CAF_LOG_TRACE("");
      // since all handles share a port, we can take any of them to query for
      // port information
      CAF_ASSERT(msg.handles.size() > 0);
      auto port = local_port(msg.handles.front());
      state.instance.remove_published_actor(port);
    },
    [=](delete_atom, const node_id& nid, actor_id aid) {
      CAF_LOG_TRACE(CAF_ARG(nid) << ", " << CAF_ARG(aid));
      state.proxies().erase(nid, aid);
    },
    [=](unpublish_atom, const actor_addr& whom, uint16_t port) -> result<void> {
      CAF_LOG_TRACE(CAF_ARG(whom) << CAF_ARG(port));
      auto cb = make_callback(
        [&](const strong_actor_ptr&, uint16_t x) -> error {
          close(hdl_by_port(x));
          return none;
        }
      );
      if (state.instance.remove_published_actor(whom, port, &cb) == 0)
        return sec::no_actor_published_at_port;
      return unit;
    },
    [=](unpublish_udp_atom, const actor_addr& whom, uint16_t port) -> result<void> {
      CAF_LOG_TRACE(CAF_ARG(whom) << CAF_ARG(port));
      auto cb = make_callback(
        [&](const strong_actor_ptr&, uint16_t x) -> error {
          close(datagram_hdl_by_port(x));
          return none;
        }
      );
      if (state.instance.remove_published_actor(whom, port, &cb) == 0)
        return sec::no_actor_published_at_port;
      return unit;
    },
    [=](close_atom, uint16_t port) -> result<void> {
      if (port == 0)
        return sec::cannot_close_invalid_port;
      // it is well-defined behavior to not have an actor published here,
      // hence the result can be ignored safely
      state.instance.remove_published_actor(port, nullptr);
      auto res = close(hdl_by_port(port));
      if (res)
        return unit;
      return sec::cannot_close_invalid_port;
    },
    [=](get_atom, const node_id& x)
    -> std::tuple<node_id, std::string, uint16_t> {
      std::string addr;
      uint16_t port = 0;
      auto hdl = state.instance.tbl().lookup_direct(x);
      if (hdl) {
        addr = visit(addr_visitor{this}, *hdl);
        port = visit(port_visitor{this}, *hdl);
      }
      return std::make_tuple(x, std::move(addr), port);
    },
    [=](tick_atom, size_t interval) {
      state.instance.handle_heartbeat(context());
      delayed_send(this, std::chrono::milliseconds{interval},
                   tick_atom::value, interval);
    },
    [=](pending_atom, datagram_handle hdl) {
      auto& ep = state.ctx_udp[hdl];
      ep.did_set_timeout = false;
      if (ep.pending.empty())
        return;
      auto i = ep.pending.begin();
      auto seq = i->first;
      if (seq == ep.seq_incoming ||
          basp::instance::is_greater(seq, ep.seq_incoming)) {
        // Skip missing messages and force delivery.
        state.deliver_pending(context(), ep, true);
      } else {
        state.drop_pending(ep, seq);
      }
    }
  };
}

resumable::resume_result basp_broker::resume(execution_unit* ctx, size_t mt) {
  ctx->proxy_registry_ptr(&state.instance.proxies());
  auto guard = detail::make_scope_guard([=] {
    ctx->proxy_registry_ptr(nullptr);
  });
  return super::resume(ctx, mt);
}

proxy_registry* basp_broker::proxy_registry_ptr() {
  return &state.instance.proxies();
}

} // namespace io
} // namespace caf
