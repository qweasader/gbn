# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0399");
  script_cve_id("CVE-2018-7889");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 18:21:00 +0000 (Fri, 12 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0399");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0399.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22814");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VUNMTXK3UTN636LOBG63UDSTVM4AF26T/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'calibre, python-html5-parser, python-lxml' package(s) announced via the MGASA-2018-0399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated calibre package fixes security vulnerability:

gui2/viewer/bookmarkmanager.py in Calibre 3.18 calls cPickle.load on
imported bookmark data, which allows remote attackers to execute arbitrary
code via a crafted .pickle file, as demonstrated by Python code that
contains an os.system call (CVE-2018-7889).

The python-html5-parser package is a new dependency for the updated calibre
package and has been included with this update.");

  script_tag(name:"affected", value:"'calibre, python-html5-parser, python-lxml' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"calibre", rpm:"calibre~3.27.1~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-html5-parser", rpm:"python-html5-parser~0.4.4~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-lxml", rpm:"python-lxml~3.8.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-lxml-docs", rpm:"python-lxml-docs~3.8.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-html5-parser", rpm:"python3-html5-parser~0.4.4~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml", rpm:"python3-lxml~3.8.0~1.1.mga6", rls:"MAGEIA6"))) {
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
