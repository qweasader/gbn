# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1718.1");
  script_cve_id("CVE-2017-7478", "CVE-2017-7479", "CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-30 14:28:46 +0000 (Fri, 30 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1718-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1718-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171718-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn-openssl1' package(s) announced via the SUSE-SU-2017:1718-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvpn-openssl1 fixes the following issues:
- Some parts of the certificate-parsing code did not always clear all
 allocated memory. This would have allowed clients to leak a few bytes of
 memory for each connection attempt, thereby facilitating a (quite
 inefficient) DoS attack on the server. [bsc#1044947, CVE-2017-7521]
- The ASN1 parsing code contained a bug that could have resulted in some
 buffers being free()d twice, and this issue could have potentially been
 triggered remotely by a VPN peer. [bsc#1044947, CVE-2017-7521]
- If clients used a HTTP proxy with NTLM authentication, a
 man-in-the-middle attacker between client and proxy could cause the
 client to crash or disclose at most 96 bytes of stack memory. The
 disclosed stack memory was likely to contain the proxy password. If the
 proxy password had not been reused, this was unlikely to compromise the
 security of the OpenVPN tunnel itself. Clients who did not use the
 --http-proxy option with ntlm2 authentication were not affected.
 [bsc#1044947, CVE-2017-7520]
- It was possible to trigger an assertion by sending a malformed IPv6
 packet. That issue could have been abused to remotely shutdown an
 openvpn server or client, if IPv6 and --mssfix were enabled and if the
 IPv6 networks used inside the VPN were known. [bsc#1044947,
 CVE-2017-7508]
- The installed sample configuration file was updated to comply to FIPS
 requirements. [bsc#988522]
- Remedy large latencies on the openVPN server during authentication
 process. [bsc#959511]
- Fix potential denial-of-service attacks found during independent audits.
 [bsc#1038713, bsc#1038709, CVE-2017-7478, bsc#1038711, CVE-2017-7479]");

  script_tag(name:"affected", value:"'openvpn-openssl1' package(s) on SUSE Linux Enterprise Server 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"openvpn-openssl1", rpm:"openvpn-openssl1~2.3.2~0.9.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-openssl1-down-root-plugin", rpm:"openvpn-openssl1-down-root-plugin~2.3.2~0.9.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
