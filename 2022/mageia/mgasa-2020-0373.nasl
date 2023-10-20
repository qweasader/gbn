# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0373");
  script_cve_id("CVE-2020-25219");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-29 04:15:00 +0000 (Sun, 29 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0373");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0373.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27302");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2372");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4514-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/CNID6EZVOVH7EZB7KFU2EON54CFDIVUR/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libproxy' package(s) announced via the MGASA-2020-0373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"url::recvline in url.cpp in libproxy 0.4.x through 0.4.15 allows a remote
HTTP server to trigger uncontrolled recursion via a response composed of an
infinite stream that lacks a newline character. This leads to stack
exhaustion. (CVE-2020-25219)");

  script_tag(name:"affected", value:"'libproxy' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64proxy-devel", rpm:"lib64proxy-devel~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64proxy-gnome", rpm:"lib64proxy-gnome~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64proxy-kde", rpm:"lib64proxy-kde~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64proxy-networkmanager", rpm:"lib64proxy-networkmanager~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64proxy-webkit", rpm:"lib64proxy-webkit~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64proxy1", rpm:"lib64proxy1~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy", rpm:"libproxy~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-devel", rpm:"libproxy-devel~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-gnome", rpm:"libproxy-gnome~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-gxsettings", rpm:"libproxy-gxsettings~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-kde", rpm:"libproxy-kde~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-networkmanager", rpm:"libproxy-networkmanager~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-pacrunner", rpm:"libproxy-pacrunner~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-perl", rpm:"libproxy-perl~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-utils", rpm:"libproxy-utils~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-webkit", rpm:"libproxy-webkit~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1", rpm:"libproxy1~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-libproxy", rpm:"python2-libproxy~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libproxy", rpm:"python3-libproxy~0.4.15~4.1.mga7", rls:"MAGEIA7"))) {
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
