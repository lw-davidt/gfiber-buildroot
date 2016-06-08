{
  'targets': [
    {
      'target_name': 'fibertv_widevine_cdm',
      'type': 'none',
      'sources': [],
      'dependencies': [
        '<(DEPTH)/cdm/cdm.gyp:widevine_ce_cdm_shared',
        '<(DEPTH)/cdm/cdm_unittests.gyp:widevine_ce_cdm_unittest',
      ],
    }
  ],
}
