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
#include "util/byte_v.h"
#include "blake2.h"
#include "cryptlib.h"
#include "lsh.h"
#include "sha.h"
#include "sha3.h"
#include "filters.h"

using namespace CryptoPP;

namespace {
    const auto ghash(auto&& hash, feistelizer::byte_v arg, feistelizer::byte_v key) -> feistelizer::byte_v
    {
        std::vector<uint8_t> ret(hash.DigestSize());
        StringSource(arg.data(), arg.size(), true /* pumpAll*/, new HashFilter(hash, new ArraySink(ret.data(), ret.size())));
        feistelizer::xor_v(ret, key);
        return ret;
    }
}

namespace feistelizer 
{
    const auto fsha256(byte_v arg, byte_v key) -> byte_v
    {
        return ghash(SHA256{}, arg, key);
    }

    const auto fsha3_256(byte_v arg, byte_v key) -> byte_v 
    {
        return ghash(SHA3_256{}, arg, key);
    }

    const auto fblake2_256(byte_v arg, byte_v key) -> byte_v
    {
        return ghash(BLAKE2b{}, arg, key);
    }

    const auto flsh_256(byte_v arg, byte_v key) ->byte_v
    {
        return ghash(LSH256{}, arg, key);
    }
};