# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0031");
  script_cve_id("CVE-2021-45960", "CVE-2021-46143", "CVE-2022-22822", "CVE-2022-22823", "CVE-2022-22824", "CVE-2022-22825", "CVE-2022-22826", "CVE-2022-22827");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-14 12:15:00 +0000 (Mon, 14 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0031");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0031.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29902");
  script_xref(name:"URL", value:"https://blog.hartwork.org/posts/expat-2-4-3-released/");
  script_xref(name:"URL", value:"https://github.com/libexpat/libexpat/blob/R_2_4_3/expat/Changes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the MGASA-2022-0031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places
in the storeAtts function in xmlparse.c can lead to realloc misbehavior
(e.g., allocating too few bytes, or only freeing memory). (CVE-2021-45960)

In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer
overflow exists for m_groupSize. (CVE-2021-46143)

addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an
integer overflow. (CVE-2022-22822)

build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an
integer overflow. (CVE-2022-22823)

defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an
integer overflow. (CVE-2022-22824)

lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer
overflow. (CVE-2022-22825)

nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an
integer overflow. (CVE-2022-22826)

storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an
integer overflow. (CVE-2022-22827)");

  script_tag(name:"affected", value:"'expat' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.2.10~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat-devel", rpm:"lib64expat-devel~2.2.10~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat1", rpm:"lib64expat1~2.2.10~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.2.10~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.2.10~1.1.mga8", rls:"MAGEIA8"))) {
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
