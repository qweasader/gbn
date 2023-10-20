# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0350");
  script_cve_id("CVE-2017-1000250");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-17 02:29:00 +0000 (Sat, 17 Feb 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0350");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0350.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21698");
  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/blueborne");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2017:2685");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the MGASA-2017-0350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information-disclosure flaw was found in the bluetoothd
implementation of the Service Discovery Protocol (SDP). A specially
crafted Bluetooth device could, without prior pairing or user
interaction, retrieve portions of the bluetoothd process memory,
including potentially sensitive information such as Bluetooth encryption
keys (CVE-2017-1000250).");

  script_tag(name:"affected", value:"'bluez' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci", rpm:"bluez-hid2hci~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez-devel", rpm:"lib64bluez-devel~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez3", rpm:"lib64bluez3~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez-devel", rpm:"libbluez-devel~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez3", rpm:"libbluez3~5.28~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.45~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~5.45~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci", rpm:"bluez-hid2hci~5.45~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez-devel", rpm:"lib64bluez-devel~5.45~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez3", rpm:"lib64bluez3~5.45~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez-devel", rpm:"libbluez-devel~5.45~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez3", rpm:"libbluez3~5.45~2.1.mga6", rls:"MAGEIA6"))) {
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
