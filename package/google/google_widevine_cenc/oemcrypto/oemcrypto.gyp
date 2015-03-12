{
  'variables': {
    'oec_mock_dir': '../../../oemcrypto/mock',
  },
  'target_defaults': {
    'defines': ['USE_BUILT_OPENSSL'],
  },
  'targets': [
    {
      'target_name': 'oemcrypto',
      'type': 'static_library',
      # TODO(jfore): Is there a way to find this relative path at run time?
      'includes': ['../../../oemcrypto/mock/oec_mock_kernel.gypi'],
      'sources': [
        'spacecast_gfcs100_device_properties.cpp',
        'spacecast_gfcs100_keybox.cpp'
      ],
      'dependencies': [
        'blue_client_key',
      ],
    },
    {
      'target_name': 'blue_client_key',
      'type': 'static_library',
      'include_dirs': ['obfuscated_rsa/include'],
      'sources': [
        'obfuscated_rsa/client_key/blue_client.cpp',
        'obfuscated_rsa/client_key/blue_client_0.cpp',
        'obfuscated_rsa/client_key/blue_client_1.cpp',
        'obfuscated_rsa/client_key/blue_client_2.cpp',
        'obfuscated_rsa/client_key/blue_client_3.cpp',
        'obfuscated_rsa/client_key/blue_client_4.cpp',
      ],
      'direct_dependent_settings': {
        'include_dirs': ['obfuscated_rsa/include'],
      },
    },
  ],
}