/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>
#include <string>
#include <vector>

// clang-format off
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
// clang-format on

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

namespace {

// Helper to set up an iovec pair for jail_get
void setJailParam(struct iovec* iov,
                  int idx,
                  const char* name,
                  void* value,
                  size_t len) {
  iov[idx * 2].iov_base = const_cast<char*>(name);
  iov[idx * 2].iov_len = strlen(name) + 1;
  iov[idx * 2 + 1].iov_base = value;
  iov[idx * 2 + 1].iov_len = len;
}

// Format IPv4 addresses as comma-separated string
std::string formatIPv4Addresses(const std::vector<struct in_addr>& addrs) {
  std::ostringstream oss;
  for (size_t i = 0; i < addrs.size(); ++i) {
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addrs[i], buf, sizeof(buf)) != nullptr) {
      if (i > 0) {
        oss << ",";
      }
      oss << buf;
    }
  }
  return oss.str();
}

// Format IPv6 addresses as comma-separated string
std::string formatIPv6Addresses(const std::vector<struct in6_addr>& addrs) {
  std::ostringstream oss;
  for (size_t i = 0; i < addrs.size(); ++i) {
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &addrs[i], buf, sizeof(buf)) != nullptr) {
      if (i > 0) {
        oss << ",";
      }
      oss << buf;
    }
  }
  return oss.str();
}

} // namespace

QueryData genFreebsdJails(QueryContext& context) {
  QueryData results;

  // Iterate through all jails using lastjid
  int lastjid = 0;

  while (true) {
    // Parameters we want to retrieve
    int jid = 0;
    int parent_jid = 0;
    char name[MAXHOSTNAMELEN] = {0};
    char path[MAXPATHLEN] = {0};
    char hostname[MAXHOSTNAMELEN] = {0};
    int securelevel = 0;
    int devfs_ruleset = 0;
    int enforce_statfs = 0;
    int children_cur = 0;
    int children_max = 0;
    int cpuset_id = 0;
    int dying = 0;
    int persist = 0;
    int ip4_count = 0;
    int ip6_count = 0;

    // First pass: get basic info and IP counts
    struct iovec iov[32];
    int idx = 0;

    setJailParam(iov, idx++, "lastjid", &lastjid, sizeof(lastjid));
    setJailParam(iov, idx++, "jid", &jid, sizeof(jid));
    setJailParam(iov, idx++, "parent", &parent_jid, sizeof(parent_jid));
    setJailParam(iov, idx++, "name", name, sizeof(name));
    setJailParam(iov, idx++, "path", path, sizeof(path));
    setJailParam(iov, idx++, "host.hostname", hostname, sizeof(hostname));
    setJailParam(iov, idx++, "securelevel", &securelevel, sizeof(securelevel));
    setJailParam(
        iov, idx++, "devfs_ruleset", &devfs_ruleset, sizeof(devfs_ruleset));
    setJailParam(
        iov, idx++, "enforce_statfs", &enforce_statfs, sizeof(enforce_statfs));
    setJailParam(
        iov, idx++, "children.cur", &children_cur, sizeof(children_cur));
    setJailParam(
        iov, idx++, "children.max", &children_max, sizeof(children_max));
    setJailParam(iov, idx++, "cpuset.id", &cpuset_id, sizeof(cpuset_id));
    setJailParam(iov, idx++, "dying", &dying, sizeof(dying));
    setJailParam(iov, idx++, "persist", &persist, sizeof(persist));
    setJailParam(iov, idx++, "ip4.addr", nullptr, 0);
    setJailParam(iov, idx++, "ip6.addr", nullptr, 0);

    int ret = jail_get(iov, idx * 2, 0);
    if (ret < 0) {
      // No more jails
      break;
    }

    // Update lastjid for next iteration
    lastjid = jid;

    // Get actual IP address counts from returned iov_len
    // ip4.addr is at idx-2 (0-indexed: idx-2), ip6.addr is at idx-1
    ip4_count = iov[(idx - 2) * 2 + 1].iov_len / sizeof(struct in_addr);
    ip6_count = iov[(idx - 1) * 2 + 1].iov_len / sizeof(struct in6_addr);

    // Second pass to get IP addresses if any exist
    std::string ip4_str;
    std::string ip6_str;

    if (ip4_count > 0) {
      std::vector<struct in_addr> ip4_addrs(ip4_count);
      struct iovec ip4_iov[4];
      setJailParam(ip4_iov, 0, "jid", &jid, sizeof(jid));
      setJailParam(ip4_iov,
                   1,
                   "ip4.addr",
                   ip4_addrs.data(),
                   ip4_count * sizeof(struct in_addr));
      if (jail_get(ip4_iov, 4, 0) >= 0) {
        ip4_str = formatIPv4Addresses(ip4_addrs);
      }
    }

    if (ip6_count > 0) {
      std::vector<struct in6_addr> ip6_addrs(ip6_count);
      struct iovec ip6_iov[4];
      setJailParam(ip6_iov, 0, "jid", &jid, sizeof(jid));
      setJailParam(ip6_iov,
                   1,
                   "ip6.addr",
                   ip6_addrs.data(),
                   ip6_count * sizeof(struct in6_addr));
      if (jail_get(ip6_iov, 4, 0) >= 0) {
        ip6_str = formatIPv6Addresses(ip6_addrs);
      }
    }

    Row r;
    r["jid"] = INTEGER(jid);
    r["parent_jid"] = INTEGER(parent_jid);
    r["name"] = name;
    r["path"] = path;
    r["hostname"] = hostname;
    r["ip4_addresses"] = ip4_str;
    r["ip6_addresses"] = ip6_str;
    r["securelevel"] = INTEGER(securelevel);
    r["devfs_ruleset"] = INTEGER(devfs_ruleset);
    r["enforce_statfs"] = INTEGER(enforce_statfs);
    r["children_cur"] = INTEGER(children_cur);
    r["children_max"] = INTEGER(children_max);
    r["cpuset_id"] = INTEGER(cpuset_id);
    r["dying"] = INTEGER(dying);
    r["persist"] = INTEGER(persist);

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery
