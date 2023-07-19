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

#include "hashes/hashes.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <gmock/gmock-matchers.h>
#include <stdio.h>

TEST(Sha256_test, Trivial) {
  std::vector<uint8_t> test{1};
  std::array<uint8_t, 32> cmp{0x4B, 0xF5, 0x12, 0x2F, 0x34, 0x45, 0x54, 0xC5,
                              0x3B, 0xDE, 0x2E, 0xBB, 0x8C, 0xD2, 0xB7, 0xE3,
                              0xD1, 0x60, 0x0A, 0xD6, 0x31, 0xC3, 0x85, 0xA5,
                              0xD7, 0xCC, 0xE2, 0x3C, 0x77, 0x85, 0x45, 0x9A};
  EXPECT_THAT(feistelizer::fsha256(test, {32}), testing::ElementsAreArray(cmp));
}

TEST(Sha3_256_test, Trivial) {
  std::vector<uint8_t> test{1};
  std::array<uint8_t, 32> cmp{0x27, 0x67, 0xF1, 0x5C, 0x8A, 0xF2, 0xF2, 0xC7,
                              0x22, 0x5D, 0x52, 0x73, 0xFD, 0xD6, 0x83, 0xED,
                              0xC7, 0x14, 0x11, 0x0A, 0x98, 0x7D, 0x10, 0x54,
                              0x69, 0x7C, 0x34, 0x8A, 0xED, 0x4E, 0x6C, 0xC7};
  EXPECT_THAT(feistelizer::fsha3_256(test, {32}),
              testing::ElementsAreArray(cmp));
}