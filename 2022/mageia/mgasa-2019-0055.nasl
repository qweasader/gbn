# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0055");
  script_cve_id("CVE-2019-2446", "CVE-2019-2448", "CVE-2019-2450", "CVE-2019-2451", "CVE-2019-2500", "CVE-2019-2501", "CVE-2019-2504", "CVE-2019-2505", "CVE-2019-2506", "CVE-2019-2508", "CVE-2019-2509", "CVE-2019-2511", "CVE-2019-2520", "CVE-2019-2521", "CVE-2019-2522", "CVE-2019-2523", "CVE-2019-2524", "CVE-2019-2525", "CVE-2019-2526", "CVE-2019-2527", "CVE-2019-2548", "CVE-2019-2552", "CVE-2019-2553", "CVE-2019-2554", "CVE-2019-2555", "CVE-2019-2556");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-18 17:14:54 +0000 (Fri, 18 Jan 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0055)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0055");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0055.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24213");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-01/msg00087.html");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-5.2#v24");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2019-0055 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Easily exploitable vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. Successful attacks of this
vulnerability can result in unauthorized access to critical data or
complete access to all Oracle VM VirtualBox accessible data
(CVE-2019-2446, CVE-2019-2448, CVE-2019-2450, CVE-2019-2451,
CVE-2019-2554, CVE-2019-2555, CVE-2019-2556).

Easily exploitable vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of
Oracle VM VirtualBox (CVE-2019-2500, CVE-2019-2524, CVE-2019-2548,
CVE-2019-2552).

Easily exploitable vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized read
access to a subset of Oracle VM VirtualBox accessible data
(CVE-2019-2501, CVE-2019-2504, CVE-2019-2505, CVE-2019-2506,
CVE-2019-2553).

Easily exploitable vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS) of
Oracle VM VirtualBox (CVE-2019-2508, CVE-2019-2509, CVE-2019-2527).

Easily exploitable vulnerability allows unauthenticated attacker with
network access via SOAP to compromise Oracle VM VirtualBox. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of Oracle VM
VirtualBox (CVE-2019-2511).

Difficult to exploit vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of Oracle
VM VirtualBox (CVE-2019-2520, CVE-2019-2521, CVE-2019-2522,
CVE-2019-2523, CVE-2019-2526).

Difficult to exploit vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.89-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.89-desktop-1.mga6~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.89-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.89-desktop586-1.mga6~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.89-server-1.mga6", rpm:"vboxadditions-kernel-4.14.89-server-1.mga6~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-doc", rpm:"virtualbox-doc~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.89-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.89-desktop-1.mga6~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.89-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.89-desktop586-1.mga6~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.89-server-1.mga6", rpm:"virtualbox-kernel-4.14.89-server-1.mga6~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.2.24~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-vboxvideo", rpm:"x11-driver-video-vboxvideo~5.2.24~1.mga6", rls:"MAGEIA6"))) {
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
