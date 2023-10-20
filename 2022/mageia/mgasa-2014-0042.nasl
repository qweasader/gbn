# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0042");
  script_cve_id("CVE-2013-4152");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0042");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0042.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2842");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12295");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'springframework' package(s) announced via the MGASA-2014-0042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated springframework packages fix security vulnerability:

Alvaro Munoz discovered a XML External Entity (XXE) injection in the Spring
Framework which can be used for conducting CSRF and DoS attacks on other sites
(CVE-2013-4152).");

  script_tag(name:"affected", value:"'springframework' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"springframework", rpm:"springframework~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-aop", rpm:"springframework-aop~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-beans", rpm:"springframework-beans~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context", rpm:"springframework-context~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context-support", rpm:"springframework-context-support~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-expression", rpm:"springframework-expression~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-instrument", rpm:"springframework-instrument~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-javadoc", rpm:"springframework-javadoc~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jdbc", rpm:"springframework-jdbc~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jms", rpm:"springframework-jms~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-orm", rpm:"springframework-orm~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-oxm", rpm:"springframework-oxm~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-struts", rpm:"springframework-struts~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-tx", rpm:"springframework-tx~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-web", rpm:"springframework-web~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc", rpm:"springframework-webmvc~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc-portlet", rpm:"springframework-webmvc-portlet~3.1.1~21.1.mga3", rls:"MAGEIA3"))) {
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
