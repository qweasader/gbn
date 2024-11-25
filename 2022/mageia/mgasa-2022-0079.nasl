# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0079");
  script_cve_id("CVE-2022-23959");
  script_tag(name:"creation_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 18:16:51 +0000 (Mon, 07 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0079");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0079.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30048");
  script_xref(name:"URL", value:"https://docs.varnish-software.com/security/VSV00008/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UMMDMQWNAE3BTSZUHXQHVAMZC5TLHLYT/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2920");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'varnish' package(s) announced via the MGASA-2022-0079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Varnish Cache before 6.6.2 and 7.x before 7.0.2, Varnish Cache 6.0 LTS
before 6.0.10, and Varnish Enterprise (Cache Plus) 4.1.x before
4.1.11r6 and 6.0.x before 6.0.9r4, request smuggling can occur for HTTP/1
connections. (CVE-2022-23959)");

  script_tag(name:"affected", value:"'varnish' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish-devel", rpm:"lib64varnish-devel~6.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish2", rpm:"lib64varnish2~6.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish-devel", rpm:"libvarnish-devel~6.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish2", rpm:"libvarnish2~6.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varnish", rpm:"varnish~6.5.1~1.2.mga8", rls:"MAGEIA8"))) {
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
