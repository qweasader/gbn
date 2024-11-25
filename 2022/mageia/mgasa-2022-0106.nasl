# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0106");
  script_cve_id("CVE-2021-4091");
  script_tag(name:"creation_date", value:"2022-03-22 04:07:04 +0000 (Tue, 22 Mar 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-01 01:05:10 +0000 (Tue, 01 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0106)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0106");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0106.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2022:0889");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30175");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the MGASA-2022-0106 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A double-free was found in the way 389-ds-base handles virtual attributes
context in persistent searches. An attacker could send a series of search
requests, forcing the server to behave unexpectedly, and crash.
(CVE-2021-4091)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-389-ds", rpm:"cockpit-389-ds~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base-devel", rpm:"lib389-ds-base-devel~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base0", rpm:"lib389-ds-base0~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base-devel", rpm:"lib64389-ds-base-devel~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base0", rpm:"lib64389-ds-base0~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svrcore-devel", rpm:"lib64svrcore-devel~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svrcore0", rpm:"lib64svrcore0~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore-devel", rpm:"libsvrcore-devel~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0", rpm:"libsvrcore0~1.4.0.26~8.2.mga8", rls:"MAGEIA8"))) {
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
