# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0368");
  script_cve_id("CVE-2021-21772");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-10 21:15:00 +0000 (Sat, 10 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0368");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0368.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29018");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/WDGGB65YBQL662M3MOBNNJJNRNURW4TG/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'act, lib3mf, openscad' package(s) announced via the MGASA-2021-0368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free vulnerability exists in the NMR::COpcPackageReader::releaseZIP()
functionality of 3MF Consortium lib3mf 2.0.0. A specially crafted 3MF file can
lead to code execution. An attacker can provide a malicious file to trigger
this vulnerability (CVE-2021-21772).

A new package 'act' is introduced to build newer version of lib3mf.

Also, openscad is rebuilt against this updated library.");

  script_tag(name:"affected", value:"'act, lib3mf, openscad' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"act", rpm:"act~1.6.0~4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib3mf", rpm:"lib3mf~2.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib3mf-devel", rpm:"lib3mf-devel~2.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib3mf2", rpm:"lib3mf2~2.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib643mf-devel", rpm:"lib643mf-devel~2.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib643mf2", rpm:"lib643mf2~2.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openscad", rpm:"openscad~2021.01~1.2.mga8", rls:"MAGEIA8"))) {
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
