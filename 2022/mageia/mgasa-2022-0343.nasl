# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0343");
  script_cve_id("CVE-2022-31001", "CVE-2022-31002", "CVE-2022-31003");
  script_tag(name:"creation_date", value:"2022-09-22 04:40:55 +0000 (Thu, 22 Sep 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-09 13:42:00 +0000 (Thu, 09 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0343)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0343");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0343.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30806");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3091");
  script_xref(name:"URL", value:"https://github.com/freeswitch/sofia-sip/security/advisories/GHSA-79jq-hh82-cv9g");
  script_xref(name:"URL", value:"https://github.com/freeswitch/sofia-sip/security/advisories/GHSA-g3x6-p824-x6hm");
  script_xref(name:"URL", value:"https://github.com/freeswitch/sofia-sip/security/advisories/GHSA-8w5j-6g2j-pxcp");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sofia-sip' package(s) announced via the MGASA-2022-0343 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can send a message with evil sdp to FreeSWITCH, which may
a cause a crash due to an out-of-bounds access. (CVE-2022-31001)
An attacker can send a message with evil sdp to FreeSWITCH, which may
cause a crash. (CVE-2022-31002)
An out-of-bounds write. (CVE-2022-31003)");

  script_tag(name:"affected", value:"'sofia-sip' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sofia-sip-devel", rpm:"lib64sofia-sip-devel~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sofia-sip-static-devel", rpm:"lib64sofia-sip-static-devel~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sofia-sip0", rpm:"lib64sofia-sip0~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsofia-sip-devel", rpm:"libsofia-sip-devel~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsofia-sip-static-devel", rpm:"libsofia-sip-static-devel~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsofia-sip0", rpm:"libsofia-sip0~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sofia-sip", rpm:"sofia-sip~1.12.11~10.1.mga8", rls:"MAGEIA8"))) {
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
