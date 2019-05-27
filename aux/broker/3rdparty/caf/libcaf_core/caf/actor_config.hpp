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

#pragma once

#include <string>
#include <functional>

#include "caf/fwd.hpp"
#include "caf/behavior.hpp"
#include "caf/input_range.hpp"
#include "caf/abstract_channel.hpp"

namespace caf {

/// Stores spawn-time flags and groups.
class actor_config {
public:
  execution_unit* host;
  int flags;
  input_range<const group>* groups;
  std::function<behavior (local_actor*)> init_fun;

  explicit actor_config(execution_unit* ptr = nullptr);

  inline actor_config& add_flag(int x) {
    flags |= x;
    return *this;
  }
};

/// @relates actor_config
std::string to_string(const actor_config& x);

} // namespace caf

