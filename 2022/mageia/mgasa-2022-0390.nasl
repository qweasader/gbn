# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0390");
  script_cve_id("CVE-2022-21620", "CVE-2022-21621", "CVE-2022-21627", "CVE-2022-39424", "CVE-2022-39425", "CVE-2022-39426");
  script_tag(name:"creation_date", value:"2022-10-28 04:27:39 +0000 (Fri, 28 Oct 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 21:15:15 +0000 (Tue, 18 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0390");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0390.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30972");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2022.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-6.1#v40");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2022-0390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the upstream 6.1.40 maintenance release that fixes
at least the following security vulnerabilities:

Vulnerability in the Oracle VM VirtualBox prior to 6.1.40 contains a
difficult to exploit vulnerability that allows high privileged attacker
with logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products (scope
change). Successful attacks of this vulnerability can result in takeover
of Oracle VM VirtualBox (CVE-2022-21620).

Vulnerability in the Oracle VM VirtualBox prior to 6.1.40 contains an easily
exploitable vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products (scope change). Successful attacks
of this vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of Oracle VM VirtualBox
(CVE-2022-21621).

Vulnerability in the Oracle VM VirtualBox prior to 6.1.40 contains an easily
exploitable vulnerability allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of Oracle VM VirtualBox (CVE-2022-21627).

Vulnerability in the Oracle VM VirtualBox prior to 6.1.40 contains a
difficult to exploit vulnerability allows unauthenticated attacker with
network access via VRDP to compromise Oracle VM VirtualBox. Successful
attacks of this vulnerability can result in takeover of Oracle VM
VirtualBox (CVE-2022-39424, CVE-2022-39425, CVE-2022-39426).

For other fixes in this update, see the referenced changelog.");

  script_tag(name:"affected", value:"'kmod-virtualbox, virtualbox' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.74-desktop-1.mga8", rpm:"virtualbox-kernel-5.15.74-desktop-1.mga8~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.74-server-1.mga8", rpm:"virtualbox-kernel-5.15.74-server-1.mga8~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.40~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.40~1.mga8", rls:"MAGEIA8"))) {
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
