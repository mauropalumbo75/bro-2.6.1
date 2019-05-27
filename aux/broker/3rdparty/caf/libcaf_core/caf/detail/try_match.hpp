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

#include <array>
#include <numeric>
#include <typeinfo>

#include "caf/atom.hpp"
#include "caf/type_nr.hpp"

#include "caf/detail/type_list.hpp"

namespace caf {
namespace detail {

struct meta_element {
  atom_value v;
  uint16_t typenr;
  const std::type_info* type;
  bool (*fun)(const meta_element&, const type_erased_tuple&, size_t);
};

bool match_element(const meta_element&, const type_erased_tuple&, size_t);

bool match_atom_constant(const meta_element&, const type_erased_tuple&, size_t);

template <class T, uint16_t TN = type_nr<T>::value>
struct meta_element_factory {
  static meta_element create() {
    return {static_cast<atom_value>(0), TN, nullptr, match_element};
  }
};

template <class T>
struct meta_element_factory<T, 0> {
  static meta_element create() {
    return {static_cast<atom_value>(0), 0, &typeid(T), match_element};
  }
};

template <atom_value V>
struct meta_element_factory<atom_constant<V>, type_nr<atom_value>::value> {
  static meta_element create() {
    return {V, type_nr<atom_value>::value, nullptr, match_atom_constant};
  }
};

template <class TypeList>
struct meta_elements;

template <class... Ts>
struct meta_elements<type_list<Ts...>> {
  std::array<meta_element, sizeof...(Ts)> arr;
  meta_elements() : arr{{meta_element_factory<Ts>::create()...}} {
    // nop
  }
};

bool try_match(const type_erased_tuple& xs, const meta_element* iter,
               size_t ps);

} // namespace detail
} // namespace caf

