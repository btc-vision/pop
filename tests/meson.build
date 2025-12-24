# Test configuration for Proof of Position (PoP)

# Unit test sources
unit_test_sources = files(
  'unit/types_test.cc',
  'unit/hash_test.cc',
  'unit/signature_test.cc',
  'unit/lmots_test.cc',
  'unit/ordering_test.cc',
  'unit/identity_test.cc',
  'unit/batch_receipt_test.cc',
  'unit/vdf_test.cc',
  'unit/finality_test.cc',
  'unit/commit_reveal_test.cc',
  'unit/account_test.cc',
  'unit/access_test.cc',
  'unit/logging_test.cc',
  'unit/crypto_comprehensive_test.cc',
  'unit/consensus_comprehensive_test.cc',
  'unit/execution_comprehensive_test.cc',
  'unit/additional_tests.cc',
  'unit/network_test.cc',
  'unit/receipt_pow_test.cc',
  'unit/eligibility_test.cc',
)

# Unit tests executable
unit_tests = executable('unit_tests',
  sources: unit_test_sources,
  dependencies: [
    pop_dep,
    gtest_dep,
    gtest_main_dep,
  ],
  install: false,
)

# Register tests
test('unit_tests', unit_tests,
  timeout: 120,
  protocol: 'gtest',
)
