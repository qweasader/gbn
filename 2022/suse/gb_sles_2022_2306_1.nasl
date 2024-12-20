# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2306.1");
  script_cve_id("CVE-2022-1292", "CVE-2022-1343", "CVE-2022-1434", "CVE-2022-1473", "CVE-2022-2068", "CVE-2022-2097");
  script_tag(name:"creation_date", value:"2022-07-07 04:41:01 +0000 (Thu, 07 Jul 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-29 18:30:53 +0000 (Wed, 29 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2306-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222306-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-3' package(s) announced via the SUSE-SU-2022:2306-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3 fixes the following issues:

CVE-2022-2068: Fixed more shell code injection issues in c_rehash.
 (bsc#1200550)

CVE-2022-1292: Properly sanitise shell metacharacters in c_rehash
 script. (bsc#1199166)

CVE-2022-1343: Fixed incorrect signature verification in
 OCSP_basic_verify (bsc#1199167).

CVE-2022-2097: Fixed partial missing encryption in AES OCB mode
 (bsc#1201099).

CVE-2022-1434: Fixed incorrect MAC key used in the RC4-MD5 ciphersuite
 (bsc#1199168).

CVE-2022-1473: Fixed resource leakage when decoding certificates and
 keys (bsc#1199169).");

  script_tag(name:"affected", value:"'openssl-3' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.0.1~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.1~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-debuginfo", rpm:"libopenssl3-debuginfo~3.0.1~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.0.1~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debuginfo", rpm:"openssl-3-debuginfo~3.0.1~150400.4.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debugsource", rpm:"openssl-3-debugsource~3.0.1~150400.4.7.1", rls:"SLES15.0SP4"))) {
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
