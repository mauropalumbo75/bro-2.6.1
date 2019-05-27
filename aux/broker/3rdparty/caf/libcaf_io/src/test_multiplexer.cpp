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

#include "caf/io/network/test_multiplexer.hpp"

#include "caf/io/datagram_servant.hpp"
#include "caf/io/doorman.hpp"
#include "caf/io/scribe.hpp"
#include "caf/raise_error.hpp"
#include "caf/scheduler/abstract_coordinator.hpp"

namespace caf {
namespace io {
namespace network {

namespace {

constexpr size_t receive_buffer_size = std::numeric_limits<uint16_t>::max();

} // namespace anonymous

test_multiplexer::scribe_data::scribe_data(shared_buffer_type input,
                                           shared_buffer_type output)
    : vn_buf_ptr(std::move(input)),
      wr_buf_ptr(std::move(output)),
      vn_buf(*vn_buf_ptr),
      wr_buf(*wr_buf_ptr),
      stopped_reading(false),
      passive_mode(false),
      ack_writes(false) {
  // nop
}

test_multiplexer::doorman_data::doorman_data()
    : port(0),
      stopped_reading(false),
      passive_mode(false) {
  // nop
}

test_multiplexer::datagram_data::
  datagram_data(shared_job_queue_type input,
                        shared_job_queue_type output)
    : vn_buf_ptr(std::move(input)),
      wr_buf_ptr(std::move(output)),
      vn_buf(*vn_buf_ptr),
      wr_buf(*wr_buf_ptr),
      rd_buf(datagram_handle::from_int(0), receive_buffer_size),
      stopped_reading(false),
      passive_mode(false),
      ack_writes(false),
      port(0),
      local_port(0),
      datagram_size(receive_buffer_size) {
  // nop
}

test_multiplexer::test_multiplexer(actor_system* sys)
    : multiplexer(sys),
      inline_runnables_(0),
      servant_ids_(0) {
  CAF_ASSERT(sys != nullptr);
}

test_multiplexer::~test_multiplexer() {
  // get rid of extra ref count
  for (auto& ptr : resumables_)
    intrusive_ptr_release(ptr.get());
}

scribe_ptr test_multiplexer::new_scribe(native_socket) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_CRITICAL("test_multiplexer::add_tcp_scribe called with native socket");
}

scribe_ptr test_multiplexer::new_scribe(connection_handle hdl) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  class impl : public scribe {
  public:
    impl(connection_handle ch, test_multiplexer* mpx) : scribe(ch), mpx_(mpx) {
      // nop
    }
    void configure_read(receive_policy::config config) override {
      mpx_->read_config(hdl()) = config;
    }
    void ack_writes(bool enable) override {
      mpx_->ack_writes(hdl()) = enable;
    }
    std::vector<char>& wr_buf() override {
      return mpx_->output_buffer(hdl());
    }
    std::vector<char>& rd_buf() override {
      return mpx_->input_buffer(hdl());
    }
    void stop_reading() override {
      mpx_->stopped_reading(hdl()) = true;
      detach(mpx_, false);
    }
    void flush() override {
      // nop
    }
    std::string addr() const override {
      return "test";
    }
    uint16_t port() const override {
      return static_cast<uint16_t>(hdl().id());
    }
    void add_to_loop() override {
      mpx_->passive_mode(hdl()) = false;
    }
    void remove_from_loop() override {
      mpx_->passive_mode(hdl()) = true;
    }
  private:
    test_multiplexer* mpx_;
  };
  CAF_LOG_DEBUG(CAF_ARG(hdl));
  auto sptr = make_counted<impl>(hdl, this);
  { // lifetime scope of guard
    guard_type guard{mx_};
    impl_ptr(hdl) = sptr;
  }
  CAF_LOG_INFO("opened connection" << sptr->hdl());
  return sptr;
}

expected<scribe_ptr> test_multiplexer::new_tcp_scribe(const std::string& host,
                                                      uint16_t port) {
  CAF_LOG_TRACE(CAF_ARG(host) << CAF_ARG(port));
  connection_handle hdl;
  { // lifetime scope of guard
    guard_type guard{mx_};
    auto i = scribes_.find(std::make_pair(host, port));
    if (i != scribes_.end()) {
      hdl = i->second;
      scribes_.erase(i);
    } else {
      return sec::cannot_connect_to_node;
    }
  }
  return new_scribe(hdl);
}

doorman_ptr test_multiplexer::new_doorman(native_socket) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_CRITICAL("test_multiplexer::add_tcp_doorman called with native socket");
}

doorman_ptr test_multiplexer::new_doorman(accept_handle hdl, uint16_t port) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  class impl : public doorman {
  public:
    impl(accept_handle ah, test_multiplexer* mpx) : doorman(ah), mpx_(mpx) {
      // nop
    }
    bool new_connection() override {
      connection_handle ch;
      { // Try to get a connection handle of a pending connect.
        guard_type guard{mpx_->mx_};
        auto& pc = mpx_->pending_connects();
        auto i = pc.find(hdl());
        if (i == pc.end())
          return false;
        ch = i->second;
        pc.erase(i);
      }
      CAF_LOG_INFO("accepted connection" << ch << "on acceptor" << hdl());
      parent()->add_scribe(mpx_->new_scribe(ch));
      return doorman::new_connection(mpx_, ch);
    }
    void stop_reading() override {
      mpx_->stopped_reading(hdl()) = true;
      detach(mpx_, false);
    }
    void launch() override {
      // nop
    }
    std::string addr() const override {
      return "test";
    }
    uint16_t port() const override {
      guard_type guard{mpx_->mx_};
      return mpx_->port(hdl());
    }
    void add_to_loop() override {
      mpx_->passive_mode(hdl()) = false;
    }
    void remove_from_loop() override {
      mpx_->passive_mode(hdl()) = true;
    }
  private:
    test_multiplexer* mpx_;
  };
  auto dptr = make_counted<impl>(hdl, this);
  { // lifetime scope of guard
    guard_type guard{mx_};
    auto& ref = doorman_data_[hdl];
    ref.ptr = dptr;
    ref.port = port;
  }
  CAF_LOG_INFO("opened port" << port << "on acceptor" << hdl);
  return dptr;
}

expected<doorman_ptr> test_multiplexer::new_tcp_doorman(uint16_t desired_port,
                                                        const char*, bool) {
  CAF_LOG_TRACE(CAF_ARG(desired_port));
  accept_handle hdl;
  uint16_t port = 0;
  { // Lifetime scope of guard.
    guard_type guard{mx_};
    if (desired_port == 0) {
      // Start with largest possible port and reverse iterate until we find a
      // port that's not assigned to a known doorman.
      port = std::numeric_limits<uint16_t>::max();
      while (is_known_port(port))
        --port;
      // Do the same for finding an acceptor handle.
      auto y = std::numeric_limits<int64_t>::max();
      while (is_known_handle(accept_handle::from_int(y)))
        --y;
      hdl = accept_handle::from_int(y);
    } else {
      auto i = doormen_.find(desired_port);
      if (i != doormen_.end()) {
        hdl = i->second;
        doormen_.erase(i);
        port = desired_port;
      } else {
        return sec::cannot_open_port;
      }
    }
  }
  return new_doorman(hdl, port);
}

datagram_servant_ptr test_multiplexer::new_datagram_servant(native_socket) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_CRITICAL("test_multiplexer::new_datagram_servant called with native socket");
}

datagram_servant_ptr
test_multiplexer::new_datagram_servant_for_endpoint(native_socket,
                                                    const ip_endpoint&) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_CRITICAL("test_multiplexer::new_datagram_servant_for_endpoint called with "
               "native socket");
}

expected<datagram_servant_ptr>
test_multiplexer::new_remote_udp_endpoint(const std::string& host,
                                          uint16_t port) {
  CAF_LOG_TRACE(CAF_ARG(host) << CAF_ARG(port));
  datagram_handle hdl;
  { // lifetime scope of guard
    guard_type guard{mx_};
    auto i = remote_endpoints_.find(std::make_pair(host, port));
    if (i != remote_endpoints_.end()) {
      hdl = i->second;
      remote_endpoints_.erase(i);
    } else {
      return sec::cannot_connect_to_node;
    }
  }
  auto ptr = new_datagram_servant(hdl, port);
  // Set state in the struct to enable direct communication?
  { // lifetime scope of guard
    guard_type guard{mx_};
    auto data = data_for_hdl(hdl);
    data->servants.emplace(hdl);
    local_port(hdl) = data->local_port;
  }
  return ptr;
}

expected<datagram_servant_ptr>
test_multiplexer::new_local_udp_endpoint(uint16_t desired_port,
                                         const char*, bool) {
  CAF_LOG_TRACE(CAF_ARG(desired_port));
  datagram_handle hdl;
  uint16_t port = 0;
  { // Lifetime scope of guard.
    guard_type guard{mx_};
    if (desired_port == 0) {
      // Start with largest possible port and reverse iterate until we find a
      // port that's not assigned to a known doorman.
      port = std::numeric_limits<uint16_t>::max();
      while (is_known_port(port))
        --port;
      // Do the same for finding a local dgram handle
      auto y = std::numeric_limits<int64_t>::max();
      while (is_known_handle(datagram_handle::from_int(y)))
        --y;
      hdl = datagram_handle::from_int(y);
    } else {
      auto i = local_endpoints_.find(desired_port);
      if (i != local_endpoints_.end()) {
        hdl = i->second;
        local_endpoints_.erase(i);
        port = desired_port;
      } else {
        return sec::cannot_open_port;
      }
    }
  }
  return new_datagram_servant(hdl, port);
}

datagram_servant_ptr test_multiplexer::new_datagram_servant(datagram_handle hdl,
                                                            uint16_t port) {
  CAF_LOG_TRACE(CAF_ARG(hdl));
  class impl : public datagram_servant {
  public:
    impl(datagram_handle dh, test_multiplexer* mpx)
        : datagram_servant(dh), mpx_(mpx) {
      // nop
    }
    bool new_endpoint(network::receive_buffer& buf) override {
      datagram_handle dhdl;
      { // Try to get a connection handle of a pending connect.
        guard_type guard{mpx_->mx_};
        auto& pe = mpx_->pending_endpoints();
        auto i = pe.find(hdl().id());
        if (i == pe.end())
          return false;
        dhdl = i->second;
        pe.erase(i);
      }
      auto data = mpx_->data_for_hdl(hdl());
      data->servants.emplace(dhdl);
      mpx_->datagram_data_.emplace(dhdl, data);
      parent()->add_hdl_for_datagram_servant(this, dhdl);
      return consume(mpx_, dhdl, buf);
    }
    void ack_writes(bool enable) override {
      mpx_->ack_writes(hdl()) = enable;
    }
    std::vector<char>& wr_buf(datagram_handle dh) override {
      auto& buf = mpx_->output_buffer(dh);
      buf.first = dh;
      return buf.second;
    }
    void enqueue_datagram(datagram_handle dh,
                          std::vector<char> buf) override {
      auto& q = mpx_->output_queue(dh);
      q.emplace_back(dh, std::move(buf));
    }
    network::receive_buffer& rd_buf() override {
      auto& buf = mpx_->input_buffer(hdl());
      return buf.second;
    }
    void stop_reading() override {
      mpx_->stopped_reading(hdl()) = true;
      detach_handles();
      detach(mpx_, false);
    }
    void launch() override {
      // nop
    }
    void flush() override {
      // nop
    }
    std::string addr() const override {
      return "test";
    }
    uint16_t port(datagram_handle dh) const override {
      return static_cast<uint16_t>(dh.id());
    }
    uint16_t local_port() const override {
      guard_type guard{mpx_->mx_};
      return mpx_->local_port(hdl());
    }
    std::vector<datagram_handle> hdls() const override {
      auto data = mpx_->data_for_hdl(hdl());
      std::vector<datagram_handle> result(data->servants.begin(),
                                          data->servants.end());
      return result;
    }
    void add_to_loop() override {
      mpx_->passive_mode(hdl()) = false;
    }
    void remove_from_loop() override {
      mpx_->passive_mode(hdl()) = true;
    }
    void add_endpoint(const ip_endpoint&, datagram_handle) override {
      CAF_CRITICAL("datagram_servant impl::add_endpoint called with ip_endpoint");
    }
    void remove_endpoint(datagram_handle dh) override {
      auto data = mpx_->data_for_hdl(hdl());
      { // lifetime scope of guard
        guard_type guard{mpx_->mx_};
        auto itr = std::find(data->servants.begin(), data->servants.end(), dh);
        if (itr != data->servants.end())
          data->servants.erase(itr);
      }
    }
    void detach_handles() override {
      auto data = mpx_->data_for_hdl(hdl());
      for (auto& p : data->servants)
        if (p != hdl())
          parent()->erase(p);
      data->servants.clear();
      data->servants.emplace(hdl());
    }
  private:
    test_multiplexer* mpx_;
  };
  auto dptr = make_counted<impl>(hdl, this);
  CAF_LOG_INFO("new datagram servant" << hdl);
  auto data = data_for_hdl(hdl);
  { // lifetime scope of guard
    guard_type guard{mx_};
    data->ptr = dptr;
    data->port = port;
    data->servants.emplace(hdl);
  }
  return dptr;
}

datagram_servant_ptr test_multiplexer::new_datagram_servant(datagram_handle,
                                                            const std::string&,
                                                            uint16_t) {
  CAF_CRITICAL("This has no implementation in the test multiplexer");
}

int64_t test_multiplexer::next_endpoint_id() {
  return servant_ids_++;
}


bool test_multiplexer::is_known_port(uint16_t x) const {
  auto pred1 = [&](const doorman_data_map::value_type& y) {
    return x == y.second.port;
  };
  auto pred2 = [&](const datagram_data_map::value_type& y) {
    return x == y.second->port;
  };
  return (doormen_.count(x) + local_endpoints_.count(x)) > 0
         || std::any_of(doorman_data_.begin(), doorman_data_.end(), pred1)
         || std::any_of(datagram_data_.begin(), datagram_data_.end(), pred2);
}

bool test_multiplexer::is_known_handle(accept_handle x) const {
  auto pred = [&](const pending_doorman_map::value_type& y) {
    return x == y.second;
  };
  return doorman_data_.count(x) > 0
         || std::any_of(doormen_.begin(), doormen_.end(), pred);
}

bool test_multiplexer::is_known_handle(datagram_handle x) const {
  auto pred1 = [&](const pending_local_datagram_endpoints_map::value_type& y) {
    return x == y.second;
  };
  auto pred2 = [&](const pending_remote_datagram_endpoints_map::value_type& y) {
    return x == y.second;
  };
  return datagram_data_.count(x) > 0
    || std::any_of(local_endpoints_.begin(), local_endpoints_.end(), pred1)
    || std::any_of(remote_endpoints_.begin(), remote_endpoints_.end(), pred2);
}

auto test_multiplexer::make_supervisor() -> supervisor_ptr {
  // not needed
  return nullptr;
}

bool test_multiplexer::try_run_once() {
  return try_exec_runnable() || try_read_data() || try_accept_connection();
}

void test_multiplexer::run_once() {
  try_run_once();
}

void test_multiplexer::run() {
  // nop
}

void test_multiplexer::provide_scribe(std::string host, uint16_t desired_port,
                                      connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(host) << CAF_ARG(desired_port) << CAF_ARG(hdl));
  guard_type guard{mx_};
  scribes_.emplace(std::make_pair(std::move(host), desired_port), hdl);
}

void test_multiplexer::provide_acceptor(uint16_t desired_port,
                                        accept_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  doormen_.emplace(desired_port, hdl);
  doorman_data_[hdl].port = desired_port;
}

void test_multiplexer::provide_datagram_servant(uint16_t desired_port,
                                                datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(desired_port) << CAF_ARG(hdl));
  guard_type guard{mx_};
  local_endpoints_.emplace(desired_port, hdl);
  auto data = data_for_hdl(hdl);
  data->local_port = desired_port;
}

void test_multiplexer::provide_datagram_servant(std::string host,
                                                uint16_t desired_port,
                                                datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(host) << CAF_ARG(desired_port) << CAF_ARG(hdl));
  guard_type guard{mx_};
  remote_endpoints_.emplace(std::make_pair(std::move(host), desired_port), hdl);
}

/// The external input buffer should be filled by
/// the test program.
test_multiplexer::buffer_type&
test_multiplexer::virtual_network_buffer(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].vn_buf;
}

test_multiplexer::write_job_queue_type&
test_multiplexer::virtual_network_buffer(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return data_for_hdl(hdl)->vn_buf;
}

test_multiplexer::buffer_type&
test_multiplexer::output_buffer(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].wr_buf;
}

test_multiplexer::buffer_type&
test_multiplexer::input_buffer(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].rd_buf;
}

test_multiplexer::write_job_type&
test_multiplexer::output_buffer(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  auto& buf = data_for_hdl(hdl)->wr_buf;
  buf.emplace_back();
  return buf.back();
}

test_multiplexer::write_job_queue_type&
test_multiplexer::output_queue(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return data_for_hdl(hdl)->wr_buf;
}

test_multiplexer::read_job_type&
test_multiplexer::input_buffer(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return data_for_hdl(hdl)->rd_buf;
}

receive_policy::config& test_multiplexer::read_config(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].recv_conf;
}

bool& test_multiplexer::ack_writes(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].ack_writes;
}

bool& test_multiplexer::ack_writes(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return data_for_hdl(hdl)->ack_writes;
}

bool& test_multiplexer::stopped_reading(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].stopped_reading;
}

bool& test_multiplexer::stopped_reading(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return data_for_hdl(hdl)->stopped_reading;
}

bool& test_multiplexer::passive_mode(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return scribe_data_[hdl].passive_mode;
}

bool& test_multiplexer::passive_mode(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return data_for_hdl(hdl)->passive_mode;
}

scribe_ptr& test_multiplexer::impl_ptr(connection_handle hdl) {
  return scribe_data_[hdl].ptr;
}

uint16_t& test_multiplexer::port(accept_handle hdl) {
  return doorman_data_[hdl].port;
}

uint16_t& test_multiplexer::port(datagram_handle hdl) {
  return data_for_hdl(hdl)->port;
}

uint16_t& test_multiplexer::local_port(datagram_handle hdl) {
  return data_for_hdl(hdl)->local_port;
}

datagram_servant_ptr& test_multiplexer::impl_ptr(datagram_handle hdl) {
  return data_for_hdl(hdl)->ptr;
}

std::set<datagram_handle>& test_multiplexer::servants(datagram_handle hdl) {
  return data_for_hdl(hdl)->servants;
}

bool& test_multiplexer::stopped_reading(accept_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return doorman_data_[hdl].stopped_reading;
}

bool& test_multiplexer::passive_mode(accept_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return doorman_data_[hdl].passive_mode;
}

doorman_ptr& test_multiplexer::impl_ptr(accept_handle hdl) {
  return doorman_data_[hdl].ptr;
}

void test_multiplexer::add_pending_connect(accept_handle src,
                                           connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  pending_connects_.emplace(src, hdl);
}

std::shared_ptr<test_multiplexer::datagram_data>
test_multiplexer::data_for_hdl(datagram_handle hdl) {
  auto itr = datagram_data_.find(hdl);
  if (itr != datagram_data_.end())
    return itr->second;
  // if it does not exist, create a new entry
  datagram_data_.emplace(hdl, std::make_shared<datagram_data>());
  return datagram_data_[hdl];
}

void test_multiplexer::prepare_connection(accept_handle src,
                                          connection_handle hdl,
                                          test_multiplexer& peer,
                                          std::string host, uint16_t port,
                                          connection_handle peer_hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_ASSERT(this != &peer);
  CAF_LOG_TRACE(CAF_ARG(src) << CAF_ARG(hdl) << CAF_ARG(host) << CAF_ARG(port)
                << CAF_ARG(peer_hdl));
  auto input = std::make_shared<buffer_type>();
  auto output = std::make_shared<buffer_type>();
  CAF_LOG_DEBUG("insert scribe data for" << CAF_ARG(hdl));
  auto res1 = scribe_data_.emplace(hdl, scribe_data{input, output});
  if (!res1.second)
    CAF_RAISE_ERROR("prepare_connection: handle already in use");
  CAF_LOG_DEBUG("insert scribe data on peer for" << CAF_ARG(peer_hdl));
  auto res2 = peer.scribe_data_.emplace(peer_hdl, scribe_data{output, input});
  if (!res2.second)
    CAF_RAISE_ERROR("prepare_connection: peer handle already in use");
  CAF_LOG_INFO("acceptor" << src << "has connection" << hdl
               << "ready for incoming connect from" << host << ":"
               << port << "from peer with connection handle" << peer_hdl);
  if (doormen_.count(port) == 0)
    provide_acceptor(port, src);
  add_pending_connect(src, hdl);
  peer.provide_scribe(std::move(host), port, peer_hdl);
}

void test_multiplexer::add_pending_endpoint(datagram_handle src,
                                            datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  pending_endpoints_.emplace(src.id(), hdl);
}

test_multiplexer::pending_connects_map& test_multiplexer::pending_connects() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return pending_connects_;
}

test_multiplexer::pending_endpoints_map& test_multiplexer::pending_endpoints() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  return pending_endpoints_;
}

bool test_multiplexer::has_pending_scribe(std::string x, uint16_t y) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  guard_type guard{mx_};
  return scribes_.count(std::make_pair(std::move(x), y)) > 0;
}

bool test_multiplexer::has_pending_remote_endpoint(std::string x,
                                                   uint16_t y) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  guard_type guard{mx_};
  return remote_endpoints_.count(std::make_pair(std::move(x), y)) > 0;
}

void test_multiplexer::accept_connection(accept_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(hdl));
  // Filled / initialized in the critical section.
  doorman_data* dd;
  { // Access `doorman_data_` and `pending_connects_` while holding `mx_`.
    guard_type guard{mx_};
    dd = &doorman_data_[hdl];
  }
  CAF_ASSERT(dd->ptr != nullptr);
  if (!dd->ptr->new_connection())
    dd->passive_mode = true;
}

bool test_multiplexer::try_accept_connection() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  // Filled / initialized in the critical section.
  std::vector<doorman_data*> doormen;
  { // Access `doorman_data_` and `pending_connects_` while holding `mx_`.
    guard_type guard{mx_};
    doormen.reserve(doorman_data_.size());
    for (auto& kvp : doorman_data_)
      doormen.emplace_back(&kvp.second);
  }
  // Try accepting a new connection on all existing doorman.
  return std::any_of(doormen.begin(), doormen.end(), [](doorman_data* x) {
    return x->ptr != nullptr ? x->ptr->new_connection() : false;
  });
}

bool test_multiplexer::try_read_data() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE("");
  // scribe_data might change while we traverse it
  std::vector<connection_handle> xs;
  xs.reserve(scribe_data_.size());
  for (auto& kvp : scribe_data_)
    xs.emplace_back(kvp.first);
  for (auto x : xs)
    if (try_read_data(x))
      return true;
  return false;
}

bool test_multiplexer::try_read_data(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(hdl));
  scribe_data& sd = scribe_data_[hdl];
  if (sd.passive_mode || sd.ptr == nullptr || sd.ptr->parent() == nullptr
      || !sd.ptr->parent()->getf(abstract_actor::is_initialized_flag)) {
    return false;
  }
  switch (sd.recv_conf.first) {
    case receive_policy_flag::exactly:
      if (sd.vn_buf.size() >= sd.recv_conf.second) {
        sd.rd_buf.clear();
        auto first = sd.vn_buf.begin();
        auto last = first + static_cast<ptrdiff_t>(sd.recv_conf.second);
        sd.rd_buf.insert(sd.rd_buf.end(), first, last);
        sd.vn_buf.erase(first, last);
        if (!sd.ptr->consume(this, sd.rd_buf.data(), sd.rd_buf.size()))
          sd.passive_mode = true;
        return true;
      }
      break;
    case receive_policy_flag::at_least:
      if (sd.vn_buf.size() >= sd.recv_conf.second) {
        sd.rd_buf.clear();
        sd.rd_buf.swap(sd.vn_buf);
        if (!sd.ptr->consume(this, sd.rd_buf.data(), sd.rd_buf.size()))
          sd.passive_mode = true;
        return true;
      }
      break;
    case receive_policy_flag::at_most:
      auto max_bytes = static_cast<ptrdiff_t>(sd.recv_conf.second);
      if (!sd.vn_buf.empty()) {
        sd.rd_buf.clear();
        auto xbuf_size = static_cast<ptrdiff_t>(sd.vn_buf.size());
        auto first = sd.vn_buf.begin();
        auto last = (max_bytes < xbuf_size) ? first + max_bytes
                                            : sd.vn_buf.end();
        sd.rd_buf.insert(sd.rd_buf.end(), first, last);
        sd.vn_buf.erase(first, last);
        if (!sd.ptr->consume(this, sd.rd_buf.data(), sd.rd_buf.size()))
          sd.passive_mode = true;
        return true;
      }
  }
  return false;
}

bool test_multiplexer::read_data() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE("");
  // scribe_data might change while we traverse it
  std::vector<connection_handle> xs;
  xs.reserve(scribe_data_.size());
  for (auto& kvp : scribe_data_)
    xs.emplace_back(kvp.first);
  long hits = 0;
  for (auto x : xs)
    if (scribe_data_.count(x) > 0)
      if (read_data(x))
        ++hits;
  return hits > 0;
}

bool test_multiplexer::read_data(connection_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(hdl));
  flush_runnables();
  if (passive_mode(hdl))
    return false;
  scribe_data& sd = scribe_data_[hdl];
  if (sd.ptr == nullptr || sd.ptr->parent() == nullptr
      || !sd.ptr->parent()->getf(abstract_actor::is_initialized_flag)) {
    return false;
  }
  // count how many data packets we could dispatch
  long hits = 0;
  for (;;) {
    switch (sd.recv_conf.first) {
      case receive_policy_flag::exactly:
        if (sd.vn_buf.size() >= sd.recv_conf.second) {
          ++hits;
          sd.rd_buf.clear();
          auto first = sd.vn_buf.begin();
          auto last = first + static_cast<ptrdiff_t>(sd.recv_conf.second);
          sd.rd_buf.insert(sd.rd_buf.end(), first, last);
          sd.vn_buf.erase(first, last);
          if (!sd.ptr->consume(this, sd.rd_buf.data(), sd.rd_buf.size()))
            passive_mode(hdl) = true;
        } else {
          return hits > 0;
        }
        break;
      case receive_policy_flag::at_least:
        if (sd.vn_buf.size() >= sd.recv_conf.second) {
          ++hits;
          sd.rd_buf.clear();
          sd.rd_buf.swap(sd.vn_buf);
          if (!sd.ptr->consume(this, sd.rd_buf.data(), sd.rd_buf.size()))
            passive_mode(hdl) = true;
        } else {
          return hits > 0;
        }
        break;
      case receive_policy_flag::at_most:
        auto max_bytes = static_cast<ptrdiff_t>(sd.recv_conf.second);
        if (!sd.vn_buf.empty()) {
          ++hits;
          sd.rd_buf.clear();
          auto xbuf_size = static_cast<ptrdiff_t>(sd.vn_buf.size());
          auto first = sd.vn_buf.begin();
          auto last = (max_bytes < xbuf_size) ? first + max_bytes
                                              : sd.vn_buf.end();
          sd.rd_buf.insert(sd.rd_buf.end(), first, last);
          sd.vn_buf.erase(first, last);
          if (!sd.ptr->consume(this, sd.rd_buf.data(), sd.rd_buf.size()))
            passive_mode(hdl) = true;
        } else {
          return hits > 0;
        }
    }
  }
}

bool test_multiplexer::read_data(datagram_handle hdl) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(hdl));
  flush_runnables();
  if (passive_mode(hdl))
    return false;
  auto ditr = datagram_data_.find(hdl);
  if (ditr == datagram_data_.end() || ditr->second->ptr->parent() == nullptr
      || !ditr->second->ptr->parent()->getf(abstract_actor::is_initialized_flag))
    return false;
  auto& data = ditr->second;
  if (data->vn_buf.back().second.empty())
    return false;
  // Since we can't swap std::vector and caf::io::network::receive_buffer
  // just copy over the data. This is for testing and not performance critical.
  auto& from = data->vn_buf.front();
  auto& to = data->rd_buf;
  to.first = from.first;
  CAF_ASSERT(to.second.capacity() > from.second.size());
  to.second.resize(from.second.size());
  std::copy(from.second.begin(), from.second.end(), to.second.begin());
  data->vn_buf.pop_front();
  auto sitr = datagram_data_.find(data->rd_buf.first);
  if (sitr == datagram_data_.end()) {
    if (!data->ptr->new_endpoint(data->rd_buf.second))
      passive_mode(hdl) = true;
  } else {
    if (!data->ptr->consume(this, data->rd_buf.first, data->rd_buf.second))
      passive_mode(hdl) = true;
  }
  return true;
}

void test_multiplexer::virtual_send(connection_handle hdl,
                                    const buffer_type& buf) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(hdl));
  auto& vb = virtual_network_buffer(hdl);
  vb.insert(vb.end(), buf.begin(), buf.end());
  read_data(hdl);
}

void test_multiplexer::virtual_send(datagram_handle dst, datagram_handle ep,
                                    const buffer_type& buf) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE(CAF_ARG(dst) << CAF_ARG(ep));
  auto& vb = virtual_network_buffer(dst);
  vb.emplace_back(ep, buf);
  read_data(dst);
}

void test_multiplexer::exec_runnable() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE("");
  resumable_ptr ptr;
  { // critical section
    guard_type guard{mx_};
    while (resumables_.empty())
      cv_.wait(guard);
    resumables_.front().swap(ptr);
    resumables_.pop_front();
  }
  exec(ptr);
}

bool test_multiplexer::try_exec_runnable() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE("");
  resumable_ptr ptr;
  { // critical section
    guard_type guard{mx_};
    if (resumables_.empty())
      return false;
    resumables_.front().swap(ptr);
    resumables_.pop_front();
  }
  exec(ptr);
  return true;
}

void test_multiplexer::flush_runnables() {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_LOG_TRACE("");
  // execute runnables in bursts, pick a small size to
  // minimize time in the critical section
  constexpr size_t max_runnable_count = 8;
  std::vector<resumable_ptr> runnables;
  runnables.reserve(max_runnable_count);
  // runnables can create new runnables, so we need to double-check
  // that `runnables_` is empty after each burst
  do {
    runnables.clear();
    { // critical section
      guard_type guard{mx_};
      while (!resumables_.empty() && runnables.size() < max_runnable_count) {
        runnables.emplace_back(std::move(resumables_.front()));
        resumables_.pop_front();
      }
    }
    for (auto& ptr : runnables)
      exec(ptr);
  } while (!runnables.empty());
}

void test_multiplexer::exec_later(resumable* ptr) {
  CAF_ASSERT(ptr != nullptr);
  CAF_LOG_TRACE("");
  switch (ptr->subtype()) {
    case resumable::io_actor:
    case resumable::function_object: {
      if (inline_runnables_ > 0) {
        --inline_runnables_;
        resumable_ptr tmp{ptr};
        exec(tmp);
        if (inline_runnable_callback_) {
          using std::swap;
          std::function<void()> f;
          swap(f, inline_runnable_callback_);
          f();
        }
      } else {
        std::list<resumable_ptr> tmp;
        tmp.emplace_back(ptr);
        guard_type guard{mx_};
        resumables_.splice(resumables_.end(), std::move(tmp));
        cv_.notify_all();
      }
      break;
    }
    default:
      system().scheduler().enqueue(ptr);
  }
}

void test_multiplexer::exec(resumable_ptr& ptr) {
  CAF_ASSERT(std::this_thread::get_id() == tid_);
  CAF_ASSERT(ptr != nullptr);
  CAF_LOG_TRACE("");
  switch (ptr->resume(this, 1)) {
    case resumable::resume_later:
      exec_later(ptr.get());
      break;
    case resumable::done:
    case resumable::awaiting_message:
      intrusive_ptr_release(ptr.get());
      break;
    default:
      ; // ignored
  }
}

} // namespace network
} // namespace io
} // namespace caf
