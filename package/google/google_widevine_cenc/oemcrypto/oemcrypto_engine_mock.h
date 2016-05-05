// Copyright 2013 Google Inc. All Rights Reserved.
//
//  Mock implementation of OEMCrypto APIs
//
#ifndef OEMCRYPTO_ENGINE_MOCK_H_
#define OEMCRYPTO_ENGINE_MOCK_H_

#include <stdint.h>
#include <time.h>
#include <map>
#include <vector>

#include <openssl/rsa.h>

#include "OEMCryptoCENC.h"  // Needed for enums only.
#include "lock.h"
#include "oemcrypto_key_mock.h"
#include "oemcrypto_keybox_mock.h"
#include "wv_cdm_types.h"

#ifndef MAX_NUMBER_OF_OEMCRYPTO_SESSIONS
#define MAX_NUMBER_OF_OEMCRYPTO_SESSIONS 64
#endif

#ifndef MAX_NONCE_PER_SECOND
#define MAX_NONCE_PER_SECOND 20
#endif

#ifndef NONCE_TABLE_SIZE
#define NONCE_TABLE_SIZE 16
#endif

namespace wvoec_mock {

class SessionContext;
class CryptoEngine;
class UsageTable;
class UsageTableEntry;

typedef uint32_t SessionId;
typedef std::map<SessionId, SessionContext*> ActiveSessions;

typedef std::vector<uint8_t> KeyId;
typedef std::map<KeyId, Key*> KeyMap;

// SessionKeyTable holds the keys for the current session
class SessionKeyTable {
 public:
  SessionKeyTable() {}
  ~SessionKeyTable();

  bool Insert(const KeyId key_id, const Key& key_data);
  Key* Find(const KeyId key_id);
  void Remove(const KeyId key_id);
  void UpdateDuration(const KeyControlBlock& control);

 private:
  KeyMap keys_;

  CORE_DISALLOW_COPY_AND_ASSIGN(SessionKeyTable);
};

class NonceTable {
 public:
  static const int kTableSize = NONCE_TABLE_SIZE;
  NonceTable() {
    for (int i = 0; i < kTableSize; ++i) {
      state_[i] = kNTStateInvalid;
    }
  }
  ~NonceTable(){};
  void AddNonce(uint32_t nonce);
  bool CheckNonce(uint32_t nonce);
  void Flush();

 private:
  enum NonceTableState { kNTStateInvalid, kNTStateValid, kNTStateFlushPending };
  NonceTableState state_[kTableSize];
  uint32_t age_[kTableSize];
  uint32_t nonces_[kTableSize];
};

class SessionContext {
 private:
  SessionContext() {}

 public:
  explicit SessionContext(CryptoEngine* ce, SessionId sid, RSA* rsa_key)
      : valid_(true),
        ce_(ce),
        id_(sid),
        current_content_key_(NULL),
        rsa_key_(rsa_key),
        allowed_schemes_(kSign_RSASSA_PSS),
        usage_entry_(NULL) {}
  ~SessionContext();

  bool isValid() { return valid_; }

  bool DeriveKeys(const std::vector<uint8_t>& master_key,
                  const std::vector<uint8_t>& mac_context,
                  const std::vector<uint8_t>& enc_context);
  bool RSADeriveKeys(const std::vector<uint8_t>& enc_session_key,
                     const std::vector<uint8_t>& mac_context,
                     const std::vector<uint8_t>& enc_context);
  bool GenerateSignature(const uint8_t* message, size_t message_length,
                         uint8_t* signature, size_t* signature_length);
  size_t RSASignatureSize();
  OEMCryptoResult GenerateRSASignature(const uint8_t* message,
                                       size_t message_length,
                                       uint8_t* signature,
                                       size_t* signature_length,
                                       RSA_Padding_Scheme padding_scheme);
  bool ValidateMessage(const uint8_t* message, size_t message_length,
                       const uint8_t* signature, size_t signature_length);
  OEMCryptoResult DecryptCENC(const uint8_t* iv, size_t block_offset,
                              const OEMCrypto_CENCEncryptPatternDesc* pattern,
                              const uint8_t* cipher_data,
                              size_t cipher_data_length, bool is_encrypted,
                              uint8_t* clear_data,
                              OEMCryptoBufferType buffer_type);

  OEMCryptoResult Generic_Encrypt(const uint8_t* in_buffer,
                                  size_t buffer_length, const uint8_t* iv,
                                  OEMCrypto_Algorithm algorithm,
                                  uint8_t* out_buffer);
  OEMCryptoResult Generic_Decrypt(const uint8_t* in_buffer,
                                  size_t buffer_length, const uint8_t* iv,
                                  OEMCrypto_Algorithm algorithm,
                                  uint8_t* out_buffer);
  OEMCryptoResult Generic_Sign(const uint8_t* in_buffer, size_t buffer_length,
                               OEMCrypto_Algorithm algorithm,
                               uint8_t* signature, size_t* signature_length);
  OEMCryptoResult Generic_Verify(const uint8_t* in_buffer, size_t buffer_length,
                                 OEMCrypto_Algorithm algorithm,
                                 const uint8_t* signature,
                                 size_t signature_length);
  void StartTimer();
  uint32_t CurrentTimer();  // (seconds).
  OEMCryptoResult LoadKeys(const uint8_t* message, size_t message_length,
                           const uint8_t* signature, size_t signature_length,
                           const uint8_t* enc_mac_key_iv,
                           const uint8_t* enc_mac_keys, size_t num_keys,
                           const OEMCrypto_KeyObject* key_array,
                           const uint8_t* pst, size_t pst_length);
  bool InstallKey(const KeyId& key_id, const std::vector<uint8_t>& key_data,
                  const std::vector<uint8_t>& key_data_iv,
                  const std::vector<uint8_t>& key_control,
                  const std::vector<uint8_t>& key_control_iv,
                  const std::vector<uint8_t>& pst, bool ctr_mode);
  bool DecryptRSAKey(const uint8_t* enc_rsa_key, size_t enc_rsa_key_length,
                     const uint8_t* wrapped_rsa_key_iv, uint8_t* pkcs8_rsa_key);
  bool EncryptRSAKey(const uint8_t* pkcs8_rsa_key, size_t enc_rsa_key_length,
                     const uint8_t* enc_rsa_key_iv, uint8_t* enc_rsa_key);
  bool LoadRSAKey(uint8_t* pkcs8_rsa_key, size_t rsa_key_length,
                  const uint8_t* message, size_t message_length,
                  const uint8_t* signature, size_t signature_length);
  OEMCryptoResult RefreshKey(const KeyId& key_id,
                             const std::vector<uint8_t>& key_control,
                             const std::vector<uint8_t>& key_control_iv);
  bool UpdateMacKeys(const std::vector<uint8_t>& mac_keys,
                     const std::vector<uint8_t>& iv);
  bool QueryKeyControlBlock(const KeyId& key_id, uint32_t* data);
  bool SelectContentKey(const KeyId& key_id);
  const Key* current_content_key(void) { return current_content_key_; }
  void set_mac_key_server(const std::vector<uint8_t>& mac_key_server) {
    mac_key_server_ = mac_key_server;
  }
  const std::vector<uint8_t>& mac_key_server() { return mac_key_server_; }
  void set_mac_key_client(const std::vector<uint8_t>& mac_key_client) {
    mac_key_client_ = mac_key_client;
  }
  const std::vector<uint8_t>& mac_key_client() { return mac_key_client_; }

  void set_encryption_key(const std::vector<uint8_t>& enc_key) {
    encryption_key_ = enc_key;
  }
  const std::vector<uint8_t>& encryption_key() { return encryption_key_; }
  uint32_t allowed_schemes() const { return allowed_schemes_; }

  void AddNonce(uint32_t nonce);
  bool CheckNonce(uint32_t nonce);
  void FlushNonces();
  void ReleaseUsageEntry();

 private:
  bool DeriveKey(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& context, int counter,
                 std::vector<uint8_t>* out);
  bool DecryptMessage(const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& message,
                      std::vector<uint8_t>* decrypted);
  bool CheckNonceOrEntry(const KeyControlBlock& key_control_block,
                         const std::vector<uint8_t>& pst);
  bool IsUsageEntryValid();
  OEMCryptoResult DecryptCBC(const uint8_t* key, const uint8_t* iv,
                             const OEMCrypto_CENCEncryptPatternDesc* pattern,
                             const uint8_t* cipher_data,
                             size_t cipher_data_length, uint8_t* clear_data);
  OEMCryptoResult PatternDecryptCTR(
      const uint8_t* key, const uint8_t* iv, size_t block_offset,
      const OEMCrypto_CENCEncryptPatternDesc* pattern,
      const uint8_t* cipher_data, size_t cipher_data_length,
      uint8_t* clear_data);
  OEMCryptoResult DecryptCTR(const uint8_t* key_u8, const uint8_t* iv,
                             size_t block_offset, const uint8_t* cipher_data,
                             size_t cipher_data_length, uint8_t* clear_data);

  bool valid_;
  CryptoEngine* ce_;
  SessionId id_;
  std::vector<uint8_t> mac_key_server_;
  std::vector<uint8_t> mac_key_client_;
  std::vector<uint8_t> encryption_key_;
  std::vector<uint8_t> session_key_;
  const Key* current_content_key_;
  SessionKeyTable session_keys_;
  NonceTable nonce_table_;
  RSA* rsa_key_;
  uint32_t allowed_schemes_;  // for RSA signatures.
  time_t timer_start_;
  UsageTableEntry* usage_entry_;

  CORE_DISALLOW_COPY_AND_ASSIGN(SessionContext);
};

class CryptoEngine {
 public:
  CryptoEngine();
  ~CryptoEngine();

  bool Initialized() { return true; }

  void Terminate();

  KeyboxError ValidateKeybox();
  WvKeybox& keybox() { return use_test_keybox_ ? test_keybox_ : keybox_; }
  WvKeybox& real_keybox() { return keybox_; }
  void UseTestKeybox() { use_test_keybox_ = true; }
  RSA* rsa_key() { return rsa_key_; }
  bool LoadTestRSAKey();

  SessionId CreateSession();

  bool DestroySession(SessionId sid);

  SessionContext* FindSession(SessionId sid);

  size_t GetNumberOfOpenSessions() { return sessions_.size(); }

  size_t GetMaxNumberOfSessions() {
    // An arbitrary limit for mock implementation.
    static const size_t kMaxSupportedOEMCryptoSessions =
        MAX_NUMBER_OF_OEMCRYPTO_SESSIONS;
    return kMaxSupportedOEMCryptoSessions;
  }

  void set_current_session_(SessionContext* current) {
    current_session_ = current;
  }

  OEMCrypto_HDCP_Capability current_hdcp_capability();
  OEMCrypto_HDCP_Capability maximum_hdcp_capability();

  UsageTable* usage_table() { return usage_table_; }
  bool local_display();
  bool closed_platform();
  bool supports_storage();
  bool supports_keybox();
  bool is_anti_rollback_hw_present();
  const char* security_level();
  uint8_t security_patch_level();

 private:
  bool LoadPkcs8RsaKey(const uint8_t* buffer, size_t length);

  SessionContext* current_session_;
  ActiveSessions sessions_;
  WvKeybox keybox_;
  WvTestKeybox test_keybox_;
  bool use_test_keybox_;
  wvcdm::Lock session_table_lock_;
  UsageTable* usage_table_;
  RSA* rsa_key_;  // If no keybox, this is baked in certificate.

  CORE_DISALLOW_COPY_AND_ASSIGN(CryptoEngine);
};

}  // namespace wvoec_mock

#endif  // OEMCRYPTO_ENGINE_MOCK_H_
