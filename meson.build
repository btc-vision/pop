project('pop', 'cpp',
  version: '0.2.0',
  license: 'MIT',
  meson_version: '>=1.0.0',
  default_options: [
    'cpp_std=c++23',
    'warning_level=3',
    'werror=false',
    'optimization=3',
    'b_lto=true',
    'b_ndebug=if-release',
  ])

# Compiler setup
cpp = meson.get_compiler('cpp')

# Dependencies
seastar_dep = dependency('seastar', required: false)
liboqs_dep = dependency('liboqs', required: true)
openssl_dep = dependency('openssl', version: '>=3.0', required: true)

# Optional wasmer dependency for WASM execution
wasmer_dep = dependency('wasmer', required: false)

# Optional test dependencies
gtest_dep = dependency('gtest', main: true, required: get_option('tests'))
gtest_main_dep = dependency('gtest_main', required: get_option('tests'))

# Core source files
core_sources = files(
  'src/core/types.cc',
  'src/core/logging.cc',
)

# Crypto source files
crypto_sources = files(
  'src/crypto/hash.cc',
  'src/crypto/signature.cc',
  'src/crypto/lmots.cc',
)

# Consensus source files
consensus_sources = files(
  'src/consensus/ordering.cc',
  'src/consensus/identity.cc',
  'src/consensus/batch_receipt.cc',
  'src/consensus/vdf.cc',
  'src/consensus/finality.cc',
  'src/consensus/commit_reveal.cc',
  'src/consensus/receipt_pow.cc',
  'src/consensus/erasure.cc',
  'src/consensus/vdf_proof.cc',
)

# State source files
state_sources = files(
  'src/state/account.cc',
)

# Execution source files
execution_sources = files(
  'src/execution/wasm/access.cc',
)

# Network source files
network_sources = files(
  'src/network/message.cc',
  'src/network/peer.cc',
  'src/network/gossip.cc',
  'src/network/eligibility.cc',
)

# Include directories
inc_dirs = include_directories('src')

# All library sources
lib_sources = [
  core_sources,
  crypto_sources,
  consensus_sources,
  state_sources,
  execution_sources,
  network_sources,
]

# Dependencies list
pop_deps = [
  liboqs_dep,
  openssl_dep,
]

# Add seastar if available
if seastar_dep.found()
  pop_deps += seastar_dep
endif

# Add wasmer if available
if wasmer_dep.found()
  pop_deps += wasmer_dep
endif

# Core library
pop_lib = static_library('pop',
  sources: lib_sources,
  include_directories: inc_dirs,
  dependencies: pop_deps,
  install: false,
)

pop_dep = declare_dependency(
  link_with: pop_lib,
  include_directories: inc_dirs,
  dependencies: pop_deps,
)

# Tests
if get_option('tests')
  subdir('tests')
endif

# Summary
summary({
  'Version': meson.project_version(),
  'Build type': get_option('buildtype'),
  'C++ standard': get_option('cpp_std'),
  'LTO enabled': get_option('b_lto'),
  'Tests enabled': get_option('tests'),
}, section: 'Configuration')

summary({
  'Seastar': seastar_dep.found(),
  'liboqs': liboqs_dep.found(),
  'OpenSSL': openssl_dep.found(),
  'Wasmer': wasmer_dep.found(),
}, section: 'Dependencies')
