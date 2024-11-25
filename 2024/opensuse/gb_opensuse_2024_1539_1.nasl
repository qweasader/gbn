# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856123");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-30171");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-13 01:00:33 +0000 (Mon, 13 May 2024)");
  script_name("openSUSE: Security Advisory for bouncycastle (SUSE-SU-2024:1539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1539-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QZZU3EK7MCVS5TGBQL47TPFRCL6XR25J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bouncycastle'
  package(s) announced via the SUSE-SU-2024:1539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bouncycastle fixes the following issues:

  Update to version 1.78.1, including fixes for:

  * CVE-2024-30171: Fixed timing side-channel attacks against RSA decryption
      (both PKCS#1v1.5 and OAEP). (bsc#1223252)

  ##");

  script_tag(name:"affected", value:"'bouncycastle' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-mail", rpm:"bouncycastle-mail~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-tls", rpm:"bouncycastle-tls~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-jmail", rpm:"bouncycastle-jmail~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-pg", rpm:"bouncycastle-pg~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-javadoc", rpm:"bouncycastle-javadoc~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-util", rpm:"bouncycastle-util~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-pkix", rpm:"bouncycastle-pkix~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle", rpm:"bouncycastle~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-mail", rpm:"bouncycastle-mail~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-tls", rpm:"bouncycastle-tls~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-jmail", rpm:"bouncycastle-jmail~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-pg", rpm:"bouncycastle-pg~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-javadoc", rpm:"bouncycastle-javadoc~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-util", rpm:"bouncycastle-util~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-pkix", rpm:"bouncycastle-pkix~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle", rpm:"bouncycastle~1.78.1~150200.3.29.1", rls:"openSUSELeap15.5"))) {
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