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

#include "derive/variants.h"
#include "hashes/hashes.h"
#include "hashes/ciphers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <gmock/gmock-matchers.h>

TEST(DeriveFunctions, Trivial)
{
    using feistelizer::byte_v;
    using feistelizer::byte_f;
    using feistelizer::f_pair;
    using raw_f = const std::vector<unsigned char> (*)(std::vector<unsigned char>, std::vector<unsigned char>);
    using craw_f = const std::vector<unsigned char> (*const *)(std::vector<unsigned char>, std::vector<unsigned char>);
    byte_v bytes{0x0, 0x1};
    std::vector<f_pair> against = feistelizer::construct(bytes);
    craw_f cmp1 = std::get<0>(against.at(0)).target<raw_f>();
    craw_f cmp2 = std::get<0>(against.at(1)).target<raw_f>();
    craw_f cmp3 = std::get<0>(against.at(2)).target<raw_f>();
    craw_f cmp4 = std::get<0>(against.at(3)).target<raw_f>();
    EXPECT_EQ(*cmp1, feistelizer::fsha256);
    EXPECT_EQ(*cmp2, feistelizer::fsha3_256);
    EXPECT_EQ(*cmp3, feistelizer::fblake2_256);
    EXPECT_EQ(*cmp4, feistelizer::flsh_256);
}

TEST(ExpandBlock, Trivial)
{
    using feistelizer::byte_v;

    byte_v onlyone{1};
    byte_v expanded = feistelizer::expand(onlyone);
    EXPECT_EQ(expanded.size(), 64);
    std::vector<uint8_t> sixtyfive;
    std::fill_n(std::back_inserter(sixtyfive), 65, 1);
    byte_v to128 = feistelizer::expand(sixtyfive);
    EXPECT_EQ(to128.size(), 128);
}

TEST(Encipher, Trivial)
{
    using feistelizer::f_pair;
    using feistelizer::byte_v;
    byte_v bytes = ranges::views::iota(0, 63) | ranges::to<std::vector<uint8_t>>();
    std::vector<f_pair> functions = feistelizer::construct(bytes);
    byte_v cipher = feistelizer::encipher(functions, bytes);
    EXPECT_THAT(cipher, testing::Not(testing::ElementsAreArray(bytes)));
    byte_v out = feistelizer::decipher(functions, cipher);
    EXPECT_THAT(out, testing::ElementsAreArray(bytes));
}