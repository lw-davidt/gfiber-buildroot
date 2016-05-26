# Copyright 2013 Google Inc. All rights reserved.
{
  # Global place to define default variables.
  # This file and the platform-specific gypi are included in every gyp file.

  'variables': {
    'company_name': '"Google"',
    'model_name': '"Spacecastgfsc100"',
    'architecture_name': '"Freescale QorIQ-LS1024A"',
    'device_name': '"Spacecastgfsc100"',
    'product_name': '"Spacecastgfsc100"',
    'buildinfo_data': '"UndefinedBuildInfo"',
    'oemcrypto_version': 11,
    'oemcrypto_target': '<(DEPTH)/platforms/spacecast/oemcrypto/oemcrypto.gyp:oec_mock',
    'oemcrypto_max_sessions': '500',
    'oemcrypto_nonce_flood_threshold': '300',
    'certificate_provision': 'true',
    'force_use_of_secure_buffers': 'false',
    'privacy_crypto_impl': 'openssl',

    # There are three protobuf configurations:
    #
    # 1) protobuf_config == 'system'
    # Use a system-wide installation of protobuf.
    # Specify the protobuf library in protobuf_lib.
    # Specify the path to protoc in protoc_bin.
    #
    # 2) protobuf_config == 'target'
    # Use an existing protobuf gyp target from your project.
    # Specify the protobuf gyp file and target in protobuf_lib_target.
    # Specify the protoc gyp file and target in protoc_host_target.
    # Specify the path to protoc in protoc_bin.
    #
    # 3) protobuf_config == 'source'  (default)
    # Build protobuf and protoc from source.
    # Make sure that a valid config.h for your target is in the source tree.
    'protobuf_config': 'system',
    'protobuf_lib': '-lprotobuf',
    'protoc_bin': '<(protoc_dir)/protoc',
  }, # end variables

  'target_defaults': {
    'cflags': ['-fPIC'],
    # These are flags passed to the compiler for C++ only.
    'cflags_cc': [
      '-std=c++11',
    ],
    'include_dirs': ['include'],
    'configurations': {
      'Debug': {
        'defines': [
          '_DEBUG',
        ],
      },
      'Release': {
        'defines': [
          'NDEBUG',
        ],
      },
    }, # end configurations
    'target_conditions': [
      ['_type=="static_library"', {
        'standalone_static_library': 1,
      }],
      ['_target_name=="widevine_ce_cdm_static"', {
        'sources/': [['exclude', 'cdm.cpp']],
        'sources': ['src/spacecast_api.cpp'],
      }],
    ], # end target_conditions
    'defines': [
      'MAX_NUMBER_OF_OEMCRYPTO_SESSIONS=<(oemcrypto_max_sessions)',
      'MAX_NONCE_PER_SECOND=<(oemcrypto_nonce_flood_threshold)',
      'PLATFORM_COMPANY_NAME_WV=<(company_name)',
      'PLATFORM_MODEL_NAME_WV=<(model_name)',
      'PLATFORM_ARCHITECTURE_NAME_WV=<(architecture_name)',
      'PLATFORM_DEVICE_NAME_WV=<(device_name)',
      'PLATFORM_PRODUCT_NAME_WV=<(product_name)',
      'PLATFORM_BUILDINFO_WV=<(buildinfo_data)',
      'PLATFORM_CERTIFICATE_PROV=<(certificate_provision)',
      'PLATFORM_REQUIRES_SECURE_BUFFERS=<(force_use_of_secure_buffers)',
      'PLATFORM_USES_CLEAR_BUFFERS=!<(force_use_of_secure_buffers)',
    ], # end defines
  }, # end target_defaults
}

