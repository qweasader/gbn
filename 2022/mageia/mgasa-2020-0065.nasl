# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0065");
  script_cve_id("CVE-2020-2674", "CVE-2020-2678", "CVE-2020-2681", "CVE-2020-2682", "CVE-2020-2689", "CVE-2020-2690", "CVE-2020-2691", "CVE-2020-2692", "CVE-2020-2693", "CVE-2020-2698", "CVE-2020-2701", "CVE-2020-2702", "CVE-2020-2703", "CVE-2020-2704", "CVE-2020-2705", "CVE-2020-2725", "CVE-2020-2726", "CVE-2020-2727");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-19 00:01:31 +0000 (Sun, 19 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0065");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0065.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26079");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2020.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-6.0#v16");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2020-0065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the upstream 6.0.16 and fixes the following security
vulnerabilities:

An easily exploitable vulnerability allows high privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of Oracle
VM VirtualBox (CVE-2020-2674, CVE-2020-2682).

A difficult to exploit vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized
creation, deletion or modification access to critical data or all Oracle
VM VirtualBox accessible data as well as unauthorized read access to a
subset of Oracle VM VirtualBox accessible data(CVE-2020-2678).

An easily exploitable vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized access
to critical data or complete access to all Oracle VM VirtualBox accessible
data (CVE-2020-2681, CVE-2020-2689, CVE-2020-2690, CVE-2020-2691,
CVE-2020-2692, CVE-2020-2704, CVE-2020-2705).

A difficult to exploit vulnerability allows high privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized access
to critical data or complete access to all Oracle VM VirtualBox accessible
data (CVE-2020-2693).

A difficult to exploit vulnerability allows high privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of Oracle
VM VirtualBox (CVE-2020-2698, CVE-2020-2701, CVE-2020-2702, CVE-2020-2726).

An easily exploitable vulnerability allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS) of
Oracle VM VirtualBox. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-virtualbox, virtualbox' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.4.12-desktop-1.mga7", rpm:"virtualbox-kernel-5.4.12-desktop-1.mga7~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.4.12-desktop586-1.mga7", rpm:"virtualbox-kernel-5.4.12-desktop586-1.mga7~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.4.12-server-1.mga7", rpm:"virtualbox-kernel-5.4.12-server-1.mga7~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.16~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.16~1.mga7", rls:"MAGEIA7"))) {
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
