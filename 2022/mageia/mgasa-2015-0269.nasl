# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0269");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0269");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0269.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/05/05/12");
  script_xref(name:"URL", value:"http://virtuoso.openlinksw.com/dataspace/doc/dav/wiki/Main/VOSNews");
  script_xref(name:"URL", value:"http://virtuoso.openlinksw.com/dataspace/doc/dav/wiki/Main/VOSNews2013");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15853");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtuoso-opensource' package(s) announced via the MGASA-2015-0269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The virtuoso-opensource package has been updated to version 6.1.8 and two
additional upstream patches from versions 7.1.0 and 7.2.0 with additional
fixes for unspecified security issues have been added.");

  script_tag(name:"affected", value:"'virtuoso-opensource' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"virtuoso-opensource", rpm:"virtuoso-opensource~6.1.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtuoso-opensource-applications", rpm:"virtuoso-opensource-applications~6.1.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtuoso-opensource-jars", rpm:"virtuoso-opensource-jars~6.1.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"virtuoso-opensource", rpm:"virtuoso-opensource~6.1.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtuoso-opensource-applications", rpm:"virtuoso-opensource-applications~6.1.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtuoso-opensource-jars", rpm:"virtuoso-opensource-jars~6.1.8~1.mga5", rls:"MAGEIA5"))) {
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
