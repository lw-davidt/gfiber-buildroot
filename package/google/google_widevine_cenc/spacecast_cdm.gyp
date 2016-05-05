{
  'targets': [
    {
      'target_name': 'spacecast_widevine_cdm',
      'type': 'none',
      'sources': [],
      'dependencies': [
        '<(DEPTH)/cdm/cdm.gyp:widevine_ce_cdm_static',
        '<(oemcrypto_target)',
      ],
    }
  ],
}