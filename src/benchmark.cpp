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

#include "benchmark/benchmark.h"
#include "derive/variants.h"
#include "hashes/hashes.h"

static void BM_Encipher(benchmark::State &state) {
  for (auto _ : state) {
    using feistelizer::byte_v;
    using feistelizer::f_pair;
    state.PauseTiming();
    byte_v bytes = ranges::views::iota(0, state.range(0)) |
                   ranges::to<std::vector<uint8_t>>();
    std::vector<f_pair> functions = feistelizer::construct(bytes);
    state.ResumeTiming();
    benchmark::DoNotOptimize(feistelizer::encipher(functions, bytes));
    // byte_v out = feistelizer::decipher(functions, cipher);
  }
}

BENCHMARK(BM_Encipher)->RangeMultiplier(2)->Range(64, 8 << 10)->UseRealTime();

BENCHMARK_MAIN();