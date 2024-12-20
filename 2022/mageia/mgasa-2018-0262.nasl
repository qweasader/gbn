# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0262");
  script_cve_id("CVE-2018-3639");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:51:06 +0000 (Wed, 14 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0262");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0262.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2018-3639");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23072");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the MGASA-2018-0262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Systems with microprocessors utilizing speculative execution and
speculative execution of memory reads before the addresses of all
prior memory writes are known may allow unauthorized disclosure of
information to an attacker with local user access via a side-channel
analysis, aka Speculative Store Bypass (SSB), Variant 4
(CVE-2018-3639).");

  script_tag(name:"affected", value:"'libvirt' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64virt-devel", rpm:"lib64virt-devel~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt0", rpm:"lib64virt0~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-utils", rpm:"libvirt-utils~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt0", rpm:"libvirt0~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-libvirt", rpm:"wireshark-libvirt~3.10.0~1.3.mga6", rls:"MAGEIA6"))) {
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
