# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0182.1");
  script_cve_id("CVE-2014-3570", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0182-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0182-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150182-1/");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv_20150108.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl097g' package(s) announced via the SUSE-SU-2015:0182-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL (compat-openssl097g) has been updated to fix various security issues.

More information can be found in the openssl advisory:
[link moved to references] .
The following issues have been fixed:
 *
 CVE-2014-3570: Bignum squaring (BN_sqr) may have produced incorrect results on some platforms, including x86_64. (bsc#912296)
 *
 CVE-2014-3572: Don't accept a handshake using an ephemeral ECDH ciphersuites with the server key exchange message omitted. (bsc#912015)
 *
 CVE-2014-8275: Fixed various certificate fingerprint issues.
(bsc#912018)
 *
 CVE-2015-0204: Only allow ephemeral RSA keys in export ciphersuites.
(bsc#912014)
 *
 CVE-2015-0205: A fix was added to prevent use of DH client certificates without sending certificate verify message. Note that compat-openssl097g is not affected by this problem, a fix was however applied to the sources. (bsc#912293)
Security Issues:
 * CVE-2014-3570
 * CVE-2014-3572
 * CVE-2014-8275
 * CVE-2015-0204
 * CVE-2015-0205");

  script_tag(name:"affected", value:"'compat-openssl097g' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~13.27.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~13.27.1", rls:"SLES10.0SP4"))) {
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
