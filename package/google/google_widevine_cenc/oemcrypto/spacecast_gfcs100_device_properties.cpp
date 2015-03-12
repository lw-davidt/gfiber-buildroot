// Copyright 2014 Google Inc. All Rights Reserved.
//
//  Mock implementation of OEMCrypto APIs
//
#include "oemcrypto_engine_mock.h"

namespace wvoec_mock {

// If local_display() returns true, we pretend we are using a built-in display,
// instead of HDMI or WiFi output.
bool CryptoEngine::local_display() {
  return false;
}

// A closed platform is permitted to use clear buffers.
bool CryptoEngine::closed_platform() {
  return false;
}

// Returns the HDCP version currently in use.
OEMCrypto_HDCP_Capability CryptoEngine::current_hdcp_capability() {
  return local_display() ? 0xFF : 0x01;
}

// Returns the max HDCP version supported.
OEMCrypto_HDCP_Capability CryptoEngine::maximum_hdcp_capability() {
  return 0x02;
}

// Returns true if the client supports persistent storage of
// offline usage table information.
bool CryptoEngine::supports_storage() {
  return true;
}

}  // namespace wvoec_mock
