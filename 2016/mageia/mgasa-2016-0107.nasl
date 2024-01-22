# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131266");
  script_cve_id("CVE-2016-1285", "CVE-2016-1286", "CVE-2016-2088");
  script_tag(name:"creation_date", value:"2016-03-14 13:57:16 +0000 (Mon, 14 Mar 2016)");
  script_version("2023-12-04T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-12-04 05:06:09 +0000 (Mon, 04 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 17:08:00 +0000 (Thu, 30 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2016-0107)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0107");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0107.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17935");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01351");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01352");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01353");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01363");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the MGASA-2016-0107 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ISC BIND before 9.10.3-P4, an error parsing input received by the rndc
control channel can cause an assertion failure in sexpr.c or alist.c
(CVE-2016-1285).

In ISC BIND before 9.10.3-P4, a problem parsing resource record signatures
for DNAME resource records can lead to an assertion failure in resolver.c
or db.c (CVE-2016-1286).

In ISC BIND before 9.10.3-P4, A response containing multiple DNS cookies
causes servers with cookie support enabled to exit with an assertion
failure in resolver.c (CVE-2016-2088).");

  script_tag(name:"affected", value:"'bind' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.10.3.P4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.10.3.P4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.10.3.P4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.10.3.P4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.10.3.P4~1.mga5", rls:"MAGEIA5"))) {
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
