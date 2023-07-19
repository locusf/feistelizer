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
#include "cryptlib.h"
#include "modes.h"
#include "filters.h"
#include "aes.h"
#include "rc5.h"
#include "rc6.h"
#include "threefish.h"



using namespace CryptoPP;

namespace {
    template<class CIPHER>
    const auto gcipher(feistelizer::byte_v arg, feistelizer::byte_v key) -> feistelizer::byte_v
    {
        typename ECB_Mode<CIPHER>::Encryption enc(key.data(), key.size());
        feistelizer::byte_m ret(32);
        CryptoPP::VectorSource ss( arg, true, new CryptoPP::StreamTransformationFilter( enc, new CryptoPP::VectorSink(ret)));
        return ret;
    }
}

namespace feistelizer
{
    const auto faes_256(byte_v data, byte_v key)
    {
        return gcipher<CryptoPP::AES>(data, key);
    }

    const auto frc5(byte_v data, byte_v key)
    {
        return gcipher<CryptoPP::RC5>(data, key);
    }

    const auto frc6(byte_v data, byte_v key)
    {
        return gcipher<CryptoPP::RC6>(data, key);
    }

    const auto fthreefish(byte_v data, byte_v key)
    {
        return gcipher<CryptoPP::Threefish256>(data, key);
    }

}