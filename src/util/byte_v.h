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
#include <cstdint>
#include <execution>
#include <functional>
#include <vector>

namespace feistelizer
{
    using byte_v = const typename std::vector<uint8_t>;
    using byte_m = typename std::vector<uint8_t>;
    void xor_v(byte_m& a, byte_m b)
    {
        std::transform(std::execution::par_unseq, a.begin(), a.end(), b.begin(), a.begin(), std::bit_xor<uint8_t>{});
    }
} // namespace