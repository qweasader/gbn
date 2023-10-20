# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0390");
  script_cve_id("CVE-2019-10132", "CVE-2019-10161", "CVE-2019-10166", "CVE-2019-10167", "CVE-2019-10168", "CVE-2019-3886");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 14:09:00 +0000 (Thu, 25 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0390");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0390.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24757");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-04/msg00207.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:1264");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:1579");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-06/msg00023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt, python-libvirt' package(s) announced via the MGASA-2019-0390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libvirt packages fix security vulnerabilities:

An information leak which allowed to retrieve the guest hostname
under readonly mode (CVE-2019-3886).

Wrong permissions in systemd admin-sock due to missing SocketMode
parameter (CVE-2019-10132).

Arbitrary file read/exec via virDomainSaveImageGetXMLDesc API
(CVE-2019-10161).

virDomainManagedSaveDefineXML API exposed to readonly clients
(CVE-2019-10166).

Arbitrary command execution via virConnectGetDomainCapabilities API
(CVE-2019-10167).

Arbitrary command execution via virConnectBaselineHypervisorCPU and
virConnectCompareHypervisorCPU APIs (CVE-2019-10168).

Also, this update contains the libvirt adjustments, that pass through
the new 'md-clear' CPU flag, to help address Intel CPU speculative
execution flaws.");

  script_tag(name:"affected", value:"'libvirt, python-libvirt' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64nss_libvirt2", rpm:"lib64nss_libvirt2~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt-devel", rpm:"lib64virt-devel~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt0", rpm:"lib64virt0~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_libvirt2", rpm:"libnss_libvirt2~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-utils", rpm:"libvirt-utils~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt0", rpm:"libvirt0~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libvirt", rpm:"python-libvirt~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-libvirt", rpm:"python2-libvirt~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libvirt", rpm:"python3-libvirt~5.5.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-libvirt", rpm:"wireshark-libvirt~5.5.0~1.mga7", rls:"MAGEIA7"))) {
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
