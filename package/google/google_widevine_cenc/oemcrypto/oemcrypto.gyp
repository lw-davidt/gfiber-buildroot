{
  'variables': {
    'oec_mock_dir': '../../../oemcrypto/mock',
  },
  'target_defaults': {
    'defines': ['USE_BUILT_OPENSSL'],
  },
  'targets': [
    {
      'target_name': 'oec_mock',
      'type': 'static_library',
      # TODO(jfore): Is there a way to find this relative path at run time?
      'includes': ['../../../oemcrypto/mock/oec_mock_kernel.gypi'],
      'sources': [
        'spacecast_gfcs100_device_properties.cpp',
        'spacecast_gfcs100_keybox.cpp'
      ],
      'include_dirs': ['obfuscated_rsa/include',],
      'sources': [
        'obfuscated_rsa/client_key/blue_client.cpp',
        'obfuscated_rsa/client_key/blue_client_0.cpp',
        'obfuscated_rsa/client_key/blue_client_1.cpp',
        'obfuscated_rsa/client_key/blue_client_2.cpp',
        'obfuscated_rsa/client_key/blue_client_3.cpp',
        'obfuscated_rsa/client_key/blue_client_4.cpp',
        'spacecast_gfcs100_device_properties.cpp',
        'spacecast_gfcs100_keybox.cpp',
      ],
    },
  ],
}