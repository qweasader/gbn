# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0123");
  script_cve_id("CVE-2022-22728");
  script_tag(name:"creation_date", value:"2023-04-07 04:12:44 +0000 (Fri, 07 Apr 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-27 03:21:56 +0000 (Sat, 27 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0123");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0123.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30778");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2PUUS3JL44UUSLJTSXE46HVKZIW7E7PE/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3269");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/08/25/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/01/02/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libapreq2' package(s) announced via the MGASA-2023-0123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in Apache libapreq2 versions 2.16 and earlier could cause a buffer
overflow while processing multipart form uploads. A remote attacker could
send a request causing a process crash which could lead to a denial of
service attack. (CVE-2022-22728)");

  script_tag(name:"affected", value:"'libapreq2' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_apreq", rpm:"apache-mod_apreq~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apreq-devel", rpm:"lib64apreq-devel~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apreq2_3", rpm:"lib64apreq2_3~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapreq-devel", rpm:"libapreq-devel~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapreq2", rpm:"libapreq2~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapreq2_3", rpm:"libapreq2_3~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libapreq2", rpm:"perl-libapreq2~2.130.0~31.1.mga8", rls:"MAGEIA8"))) {
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
