/*
* feistelizer creates ciphers on the fly
* Copyright (C) 2023 Aleksi Suomalainen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#include "hashes/ciphers.h"
#include "hashes/hashes.h"
#include "util/byte_v.h"
#include <algorithm>
#include <cstdint>
#include <execution>
#include <functional>
#include <iterator>
#include <mutex>
#include <ranges>
#include <tuple>
#include <variant>
#include <vector>

#include <range/v3/all.hpp>
using namespace ranges;
namespace feistelizer {
constexpr uint8_t BLOCK_SIZE = 64;
using byte_f = std::function<byte_v(byte_v, byte_v)>;
using f_pair = std::pair<byte_f, byte_v>;
const std::vector<byte_f> functions{byte_f{&feistelizer::fsha256},
                                    byte_f{&feistelizer::fsha3_256},
                                    byte_f{&feistelizer::fblake2_256},
                                    byte_f{&feistelizer::flsh_256},
                                    byte_f{&feistelizer::faes_256},
                                    byte_f{&feistelizer::fthreefish},
                                    byte_f{&feistelizer::frc5},
                                    byte_f{&feistelizer::frc6}};

const auto construct(byte_v data) -> const std::vector<f_pair> {
  std::vector<f_pair> ret;
  for (const auto v : views::iota(0, 16)) {
    // KEY DERIVATION EXCESSIVELY NAIVE
    ret.emplace_back(functions.at(v % functions.size()),
                     data | views::stride(2) | views::cycle | views::take(32) |
                         ranges::to<std::vector<uint8_t>>);
  }
  return ret;
}

const auto expand(byte_v in) -> byte_v {
  uint8_t padding = BLOCK_SIZE - (in.size() % BLOCK_SIZE);
  std::vector<uint8_t> out = in;
  out.reserve(in.size() + padding);
  std::fill_n(std::back_inserter(out), padding, padding);
  return out;
}

// Flattens a range of ranges by iterating the inner
// ranges in round-robin fashion.
template <class Rngs>
class interleave_view : public view_facade<interleave_view<Rngs>> {
  friend range_access;
  std::vector<range_value_t<Rngs>> rngs_;
  struct cursor;
  cursor begin_cursor() {
    return {0, &rngs_,
            views::transform(rngs_, ranges::begin) | to<std::vector>};
  }

public:
  interleave_view() = default;
  explicit interleave_view(Rngs rngs)
      : rngs_(std::move(rngs) | to<std::vector>) {}
};

template <class Rngs> struct interleave_view<Rngs>::cursor {
  std::size_t n_;
  std::vector<range_value_t<Rngs>> *rngs_;
  std::vector<iterator_t<range_value_t<Rngs>>> its_;
  decltype(auto) read() const { return *its_[n_]; }
  void next() {
    if (0 == ((++n_) %= its_.size()))
      for_each(its_, [](auto &it) { ++it; });
  }
  bool equal(default_sentinel_t) const {
    if (n_ != 0)
      return false;
    auto ends = *rngs_ | views::transform(ranges::end);
    return its_.end() != std::mismatch(its_.begin(), its_.end(), ends.begin(),
                                       std::not_equal_to<>{})
                             .first;
  }
  CPP_member auto equal(cursor const &that) const
      -> CPP_ret(bool)(requires forward_range<range_value_t<Rngs>>) {
    return n_ == that.n_ && its_ == that.its_;
  }
};

// In:  range<range<T>>
// Out: range<T>, flattened by walking the ranges
//                round-robin fashion.
auto interleave() {
  return make_view_closure([](auto &&rngs) {
    using Rngs = decltype(rngs);
    return interleave_view<views::all_t<Rngs>>(
        views::all(std::forward<Rngs>(rngs)));
  });
}

const auto unexpand(byte_v in) -> byte_v {
  uint8_t padding = in.back();
  return in | views::take(in.size() - padding) | to<std::vector>();
}

template<class Iter>
const auto cipher(Iter fbegin,
                  Iter fend, byte_v data,
                  bool odd) -> byte_v
{
  std::vector<uint8_t> out;
  std::vector<uint8_t> expanded = expand(data);
  out.reserve(expanded.size());
  std::mutex m;
  auto chunked =
      data | ranges::views::chunk(BLOCK_SIZE) | ranges::views::common;
  std::for_each(std::execution::par, chunked.begin(), chunked.end(),
                [&](const auto &blockv) {
                  uint32_t loop = 0;
                  auto halves = blockv | ranges::views::chunk(BLOCK_SIZE / 2);
                  auto left =
                      halves | ranges::views::take(1) | interleave() |
                      to<std::vector>();
                  auto right =
                      halves | ranges::views::drop(1) | interleave() |
                      to<std::vector>();
                  std::for_each(std::execution::par, fbegin,
                                fend, [&](f_pair fp) {
                                  auto &[p, key] = fp;
                                  if ((loop & 1) == static_cast<int>(odd)) {
                                    auto res = std::invoke(p, right, key);
                                    xor_v(left, res);
                                  } else {
                                    auto res = std::invoke(p, left, key);
                                    xor_v(right, res);
                                  }
                                  loop++;
                                });
                  std::copy(std::execution::seq, left.begin(), left.end(),
                            std::back_inserter(out));
                  std::copy(std::execution::seq, right.begin(), right.end(),
                            std::back_inserter(out));
                });

  return out;
}

const auto encipher(const std::vector<f_pair> functions, byte_v data)
    -> byte_v {
  return cipher(functions.cbegin(), functions.cend(), data, true);
}
const auto decipher(const std::vector<f_pair> functions, byte_v data) {

  return cipher(functions.crbegin(), functions.crend(), data, false);
}

} // namespace feistelizer