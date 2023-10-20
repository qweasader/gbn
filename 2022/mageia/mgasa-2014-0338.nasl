# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0338");
  script_cve_id("CVE-2014-3528");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0338)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0338");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0338.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13838");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2014-3528-advisory.txt");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2316-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the MGASA-2014-0338 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated subversion packages fix security vulnerability:

Bert Huijben discovered that Subversion did not properly handle cached
credentials. A malicious server could possibly use this issue to obtain
credentials cached for a different server (CVE-2014-3528).

The subversion package has been patched to fix this issue.");

  script_tag(name:"affected", value:"'subversion' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svn-gnome-keyring0", rpm:"lib64svn-gnome-keyring0~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svn-kwallet0", rpm:"lib64svn-kwallet0~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svnjavahl1", rpm:"lib64svnjavahl1~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvn-gnome-keyring0", rpm:"libsvn-gnome-keyring0~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvn-kwallet0", rpm:"libsvn-kwallet0~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvnjavahl1", rpm:"libsvnjavahl1~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-svn-devel", rpm:"perl-svn-devel~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-svn-devel", rpm:"python-svn-devel~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-svn", rpm:"ruby-svn~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-svn-devel", rpm:"ruby-svn-devel~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-gnome-keyring-devel", rpm:"subversion-gnome-keyring-devel~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-kwallet-devel", rpm:"subversion-kwallet-devel~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svn-javahl", rpm:"svn-javahl~1.7.14~1.2.mga3", rls:"MAGEIA3"))) {
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
