# feistelizer creates ciphers on the fly
# Copyright (C) 2023 Aleksi Suomalainen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

project('feistelizer', 'c', 'cpp',
  license: 'GPL-3.0',
  license_files: 'LICENSE',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++20', 'build.cpp_std=c++20', 'buildtype=custom', 'optimization=g', 'debug=true'])

basic_hash_src = ['src/basic_hash.cpp']

basic_derive_src = ['src/basic_derive.cpp']

benchmark_src = ['src/benchmark.cpp']

inc = include_directories('cryptopp', 'src')

make = find_program('make')

cpp = meson.get_compiler('cpp')

range = subproject('range-v3')

range_dep = range.get_variable('range_dep')

gtest = subproject('gtest')

gtest_dep = gtest.get_variable('gtest_main_dep')

gmock_dep = gtest.get_variable('gmock_dep')

benchmark = subproject('google-benchmark')

benchmark_dep = benchmark.get_variable('google_benchmark_dep')

cryptopp_tgt = custom_target('cryptopp', 
        output: ['libcryptopp.a'],
        command: [make, '-j4' , '-C', '@CURRENT_SOURCE_DIR@cryptopp', 'LIBDIR=', 'DESTDIR='+ meson.current_build_dir(), 'static', 'install-lib'],
        console: true,
        env: 'CPPFLAGS=' +' '.join(get_option('build.cpp_args') + get_option('cpp_args') + (get_option('warning_level') == '3' ? ['-Wall', '-Wextra', '-Wpedantic'] : ['-Wall']) + ['-O' + get_option('optimization')] + (get_option('debug') ? ['-g', '-pg'] : [])),
        build_by_default: true,
        install: true,
        install_dir: 'cryptopp',
)

cryptopp_dep = declare_dependency(sources: cryptopp_tgt)

basic_hash_exe = executable('basic_hash_test', basic_hash_src,
  install : true,
  include_directories: inc,
  link_args: ['-pg'],
  dependencies: [gtest_dep, gmock_dep, range_dep, cryptopp_dep])

test('basic_hash_test', basic_hash_exe)

basic_derive_exe = executable('basic_derive_test', basic_derive_src,
  install : true,
  include_directories: inc,
  cpp_args: ['-fconcepts-diagnostics-depth=3'],
  link_args: ['-pg'],
  dependencies: [gtest_dep, gmock_dep, range_dep, cryptopp_dep])

benchmark_exe = executable('feistelizer_benchmark', benchmark_src,
  include_directories: inc,
  link_args: ['-pg'],
  dependencies: [range_dep, benchmark_dep, cryptopp_dep])

test('basic_derive_test', basic_derive_exe)