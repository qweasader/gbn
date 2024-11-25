# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1183.2");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-06-15 15:14:35 +0000 (Mon, 15 Jun 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1183-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1183-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151183-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2015:1183-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL was updated to fix several security issues.
CVE-2015-4000: The Logjam Attack ( weakdh.org ) has been addressed by rejecting connections with DH parameters shorter than 1024 bits.
We now also generate 2048-bit DH parameters by default.
CVE-2015-1789: An out-of-bounds read in X509_cmp_time was fixed.
CVE-2015-1790: A PKCS7 decoder crash with missing EnvelopedContent was fixed.
fixed a timing side channel in RSA decryption (bnc#929678)
Additional changes:
In the default SSL cipher string EXPORT ciphers are now disabled. This will only get active if applications get rebuilt and actually use this string. (bnc#931698)
Security Issues:
CVE-2015-1789 CVE-2015-1790 CVE-2015-4000");

  script_tag(name:"affected", value:"'OpenSSL' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~13.31.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~13.31.1", rls:"SLES10.0SP4"))) {
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
