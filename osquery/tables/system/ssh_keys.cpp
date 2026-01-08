/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

#include <boost/algorithm/string.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace osquery {
namespace tables {

extern const std::string kSSHUserKeysDir = ".ssh";

const std::string kOpenSshHeader = "-----BEGIN OPENSSH PRIVATE KEY-----";

// The first bytes of an OpenSSH key are |key type|length of cipher name|cipher
// name| so all unencrypted ed25519 keys should start with the value below
// (encoded in base64) This magic string is (hex-ified):
//  6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00 00 00 00 04 6e 6f 6e 65
// |--------------------------------------------|-----------|----------|
// | o  p  e  n  s  s  h  -  k  e  y  -  v  1 \0|          4| n  o  n e|
const std::string kOpenSshUnencryptedPrefix = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";

// openssl can't currently parse the new openssh keys
bool isOpenSSHKey(const std::string& keys_content) {
  return boost::starts_with(keys_content, kOpenSshHeader);
}

// `true` if the openssh key is encrypted, `false` otherwise.
bool isOpenSSHKeyEncrypted(const std::string& keys_content) {
  const std::string prefix = keys_content.substr(
      kOpenSshHeader.size() + 1, kOpenSshUnencryptedPrefix.size());
  return prefix != kOpenSshUnencryptedPrefix;
}

// Parse key type, length, and security bits from OpenSSH format keys
// Returns the key type name (e.g., "ed25519"), and sets key_length and key_security_bits
std::string getOpenSSHKeyType(const std::string& keys_content,
                              int& key_length,
                              int& key_security_bits) {
  // Find the base64-encoded body after the header
  auto start = keys_content.find('\n');
  if (start == std::string::npos) {
    return "";
  }
  start++;

  // Find the end marker
  auto end = keys_content.find("-----END");
  if (end == std::string::npos || end <= start) {
    return "";
  }

  // Extract and clean base64 content
  std::string base64_content;
  for (size_t i = start; i < end; i++) {
    char c = keys_content[i];
    if (c != '\n' && c != '\r' && c != ' ') {
      base64_content += c;
    }
  }

  // Decode base64 using OpenSSL
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bmem = BIO_new_mem_buf(base64_content.c_str(), base64_content.size());
  bmem = BIO_push(b64, bmem);
  BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

  std::vector<unsigned char> decoded(base64_content.size());
  int decoded_len = BIO_read(bmem, decoded.data(), decoded.size());
  BIO_free_all(bmem);

  if (decoded_len < 50) {
    return "";
  }

  // OpenSSH format: magic(15) + ciphername(4+len) + kdfname(4+len) + kdfopts(4+len) + numkeys(4) + pubkey(4+len)
  // Inside pubkey: keytype(4+len) + ...
  size_t pos = 15;  // Skip "openssh-key-v1\0"

  // Skip cipher name
  if (pos + 4 > static_cast<size_t>(decoded_len)) return "";
  uint32_t cipher_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
  pos += 4 + cipher_len;

  // Skip kdf name
  if (pos + 4 > static_cast<size_t>(decoded_len)) return "";
  uint32_t kdf_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
  pos += 4 + kdf_len;

  // Skip kdf options
  if (pos + 4 > static_cast<size_t>(decoded_len)) return "";
  uint32_t kdfopts_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
  pos += 4 + kdfopts_len;

  // Skip number of keys
  pos += 4;

  // Read public key blob length
  if (pos + 4 > static_cast<size_t>(decoded_len)) return "";
  uint32_t pubkey_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
  pos += 4;

  if (pubkey_len == 0 || pos + 4 > static_cast<size_t>(decoded_len)) return "";

  // Read key type string length (inside public key blob)
  uint32_t keytype_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
  pos += 4;

  if (keytype_len == 0 || keytype_len > 64 || pos + keytype_len > static_cast<size_t>(decoded_len)) return "";

  std::string keytype(reinterpret_cast<char*>(&decoded[pos]), keytype_len);
  pos += keytype_len;

  // Extract key length and security bits based on key type
  if (keytype == "ssh-ed25519") {
    // Ed25519 has fixed 256-bit keys with 128-bit security
    key_length = 256;
    key_security_bits = 128;
    return "ed25519";
  }

  if (keytype == "ssh-rsa") {
    // RSA public key format: e (exponent) + n (modulus)
    // Key length is the bit length of the modulus n
    // Skip e (exponent)
    if (pos + 4 > static_cast<size_t>(decoded_len)) return "rsa";
    uint32_t e_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
    pos += 4 + e_len;

    // Read n (modulus) length
    if (pos + 4 > static_cast<size_t>(decoded_len)) return "rsa";
    uint32_t n_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
    pos += 4;

    if (n_len == 0 || pos + n_len > static_cast<size_t>(decoded_len)) return "rsa";

    // Calculate bit length of modulus (accounting for leading zero byte if present)
    size_t n_bytes = n_len;
    if (decoded[pos] == 0 && n_len > 1) {
      n_bytes--;  // Leading zero byte for sign, don't count it
    }
    key_length = static_cast<int>(n_bytes * 8);

    // RSA security bits approximation (based on NIST SP 800-57)
    if (key_length >= 15360) key_security_bits = 256;
    else if (key_length >= 7680) key_security_bits = 192;
    else if (key_length >= 3072) key_security_bits = 128;
    else if (key_length >= 2048) key_security_bits = 112;
    else if (key_length >= 1024) key_security_bits = 80;
    else key_security_bits = 64;

    return "rsa";
  }

  if (keytype == "ssh-dss") {
    // DSA public key format: p + q + g + y
    // Key length is the bit length of p
    if (pos + 4 > static_cast<size_t>(decoded_len)) return "dsa";
    uint32_t p_len = (decoded[pos] << 24) | (decoded[pos+1] << 16) | (decoded[pos+2] << 8) | decoded[pos+3];
    pos += 4;

    if (p_len == 0 || pos + p_len > static_cast<size_t>(decoded_len)) return "dsa";

    size_t p_bytes = p_len;
    if (decoded[pos] == 0 && p_len > 1) {
      p_bytes--;
    }
    key_length = static_cast<int>(p_bytes * 8);

    // DSA security is limited by the 160-bit q parameter (80 bits security max for standard DSA)
    key_security_bits = 80;
    return "dsa";
  }

  if (keytype == "ecdsa-sha2-nistp256") {
    key_length = 256;
    key_security_bits = 128;
    return "ecdsa-p256";
  }

  if (keytype == "ecdsa-sha2-nistp384") {
    key_length = 384;
    key_security_bits = 192;
    return "ecdsa-p384";
  }

  if (keytype == "ecdsa-sha2-nistp521") {
    key_length = 521;
    key_security_bits = 256;
    return "ecdsa-p521";
  }

  return keytype;  // Return as-is for unknown types (key_length/security_bits unchanged)
}

// parsePrivateKey returns true iff the key is valid.
// Tries to parse the .PEM using openssl. If that fails, it checks
// if it's an openssh key.
bool parsePrivateKey(const std::string& keys_content,
                     int& key_type,
                     std::string& key_type_name,
                     std::string& key_group_name,
                     int& key_length,
                     int& key_security_bits,
                     bool& is_encrypted) {
  BIO* bio_stream = BIO_new(BIO_s_mem());
  auto const bio_stream_guard =
      scope_guard::create([bio_stream]() { BIO_free(bio_stream); });
  BIO_write(bio_stream, keys_content.c_str(), keys_content.size());
  if (bio_stream == nullptr) {
    return false;
  }

  // PEM_read_bio_PrivateKey calls passwordCallback
  // if the private key is encrypted. We don't care what the key is;
  // only whether or not it's encrypted.
  auto passwordCallback = [](char*, int, int, void* u) {
    bool* encrypted_ptr = reinterpret_cast<bool*>(u);
    *encrypted_ptr = true;
    return -1; // let openssl know that the passwordCallback failed
  };

  bool encrypted = false;
  auto pkey = PEM_read_bio_PrivateKey(bio_stream,
                                      nullptr,
                                      passwordCallback,
                                      reinterpret_cast<void*>(&encrypted));
  is_encrypted = encrypted;
  auto const pkey_guard =
      scope_guard::create([pkey]() { EVP_PKEY_free(pkey); });

  if (pkey == nullptr) {
    if (encrypted) {
      key_type = EVP_PKEY_NONE;
      return true;
    }
    // A later version of OpenSSL may add support for openssh keys. If so,
    // we can delete this conditional.
    if (isOpenSSHKey(keys_content)) {
      key_type = EVP_PKEY_NONE;
      key_type_name = getOpenSSHKeyType(keys_content, key_length, key_security_bits);
      is_encrypted = isOpenSSHKeyEncrypted(keys_content);
      return true;
    }
    // if openssl can't parse the key and it doesn't start with the openssh
    // header, it's proabably not a valid key.
    return false;
  }
  key_type = EVP_PKEY_base_id(pkey);
  key_length = EVP_PKEY_bits(pkey);
  key_security_bits = EVP_PKEY_security_bits(pkey);
  // openssl group names are all under 24 chars today, leave some extra room
  char groupname[32];
  size_t gname_len;
  int status;
  status =
      EVP_PKEY_get_group_name(pkey, groupname, sizeof(groupname), &gname_len);
  if (status) {
    key_group_name.assign(groupname, gname_len);
  }
  return true;
}

std::string keyTypeAsString(int key_type) {
  switch (key_type) {
  case EVP_PKEY_RSA:
  case EVP_PKEY_RSA2:
    return "rsa";
  case EVP_PKEY_DSA:
  case EVP_PKEY_DSA1:
  case EVP_PKEY_DSA2:
  case EVP_PKEY_DSA3:
  case EVP_PKEY_DSA4:
    return "dsa";
  case EVP_PKEY_DH:
  case EVP_PKEY_DHX:
    return "dh";
  case EVP_PKEY_EC:
    return "ec";
  case EVP_PKEY_HMAC:
    return "hmac";
  case EVP_PKEY_CMAC:
    return "cmac";
  default:
    return "";
  }
}

void genSSHkeyForHosts(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results,
                       Logger& logger) {
  // Get list of files in directory
  boost::filesystem::path keys_dir = directory;
  keys_dir /= kSSHUserKeysDir;
  std::vector<std::string> files_list;
  auto status = listFilesInDirectory(keys_dir, files_list, false);
  if (!status.ok()) {
    return;
  }

  // Go through each file
  for (const auto& kfile : files_list) {
    std::string keys_content;
    auto s = readFile(kfile, keys_content);
    if (!s.ok()) {
      // Cannot read a specific keys file.
      logger.log(google::GLOG_WARNING, s.getMessage());
      continue;
    }
    int key_type;
    std::string key_type_name;
    std::string key_group_name;
    int key_length = -1;
    int key_security_bits = -1;
    bool encrypted;
    bool parsed = parsePrivateKey(keys_content,
                                  key_type,
                                  key_type_name,
                                  key_group_name,
                                  key_length,
                                  key_security_bits,
                                  encrypted);
    if (parsed) {
      Row r;
      r["pid_with_namespace"] = "0";
      r["uid"] = uid;
      r["path"] = kfile;
      r["encrypted"] = encrypted ? "1" : "0";
      // Use OpenSSH key type name if available, otherwise use OpenSSL key type
      r["key_type"] = key_type_name.empty() ? keyTypeAsString(key_type) : key_type_name;
      r["key_group_name"] = key_group_name;
      r["key_length"] = INTEGER(key_length);
      r["key_security_bits"] = INTEGER(key_security_bits);
      results.push_back(r);
    }
  }
}

QueryData getUserSshKeysImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeyForHosts(
          uid->second, gid->second, directory->second, results, logger);
    }
  }

  return results;
}

QueryData getUserSshKeys(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "user_ssh_keys", getUserSshKeysImpl);
  } else {
    GLOGLogger logger;
    return getUserSshKeysImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
