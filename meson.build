project('feistelizer', 'c', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++20'])

src = ['src/hash/functions.cpp', 'src/feistelizer.cpp', 'libecc/src/external_deps/rand.c']

inc = include_directories('libecc/src')

make = find_program('make')

libecc_tgt = custom_target('libecc', 
        output: ['libec.a', 'libsign.a', 'libarith.a'],
        command: [make, '-C', '@CURRENT_SOURCE_DIR@libecc', 'BUILD_DIR=' + meson.current_build_dir(), 'V=1', 'WITH_STDLIB=1', 'EXTRA_CFLAGS="-DUSER_NN_BIT_LEN=4096"', 'debug'],
        console: true,
        build_by_default: true,
        install: true,
        install_dir: 'libecc',
)

cpp = meson.get_compiler('cpp')

exe = executable('feistelizer', src,
  install : true,
  include_directories: inc,
  c_args: ['-DWITH_STDLIB', '-DUSER_NN_BIT_LEN=4096'],
  cpp_args: ['-DWITH_STDLIB', '-DUSER_NN_BIT_LEN=4096'],
  link_args: ['-L.', '-lec', '-larith', '-lsign'])

test('basic', exe)
