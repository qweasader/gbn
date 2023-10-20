# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0385");
  script_cve_id("CVE-2021-2409", "CVE-2021-2442", "CVE-2021-2443", "CVE-2021-2454");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-23 13:30:00 +0000 (Fri, 23 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0385)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0385");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0385.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29279");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2021.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-6.1#v24");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2021-0385 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the upstream 6.1.24 maintenance release that fixes
at least the following security vulnerabilities:

An easily exploitable vulnerability in the Oracle VM VirtualBox (component:
Core) prior to 6.1.24 allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in takeover of Oracle VM VirtualBox (CVE-2021-2409).

An easily exploitable vulnerability in the Oracle VM VirtualBox (component:
Core) prior to 6.1.24 allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of Oracle VM VirtualBox
(CVE-2021-2442).

An easily exploitable vulnerability in the Oracle VM VirtualBox (component:
Core) prior to 6.1.24 allows high privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well
as unauthorized update, insert or delete access to some of Oracle VM
VirtualBox accessible data and unauthorized read access to a subset of
Oracle VM VirtualBox accessible data (CVE-2021-2443).

An difficult to exploit vulnerability in the Oracle VM VirtualBox (component:
Core) prior to 6.1.24 allows low privileged attacker with logon to the
infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
VirtualBox. Successful attacks of this vulnerability can result in takeover
of Oracle VM VirtualBox (CVE-2021-2454).

For other upstream fixes in this update, see the referenced changelog.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.1.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.24~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.1.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.1.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.52-desktop-1.mga8", rpm:"virtualbox-kernel-5.10.52-desktop-1.mga8~6.1.24~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.52-server-1.mga8", rpm:"virtualbox-kernel-5.10.52-server-1.mga8~6.1.24~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.24~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.24~1.1.mga8", rls:"MAGEIA8"))) {
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
