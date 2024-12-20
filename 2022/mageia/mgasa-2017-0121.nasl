# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0121");
  script_cve_id("CVE-2017-7692");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 00:47:52 +0000 (Tue, 25 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0121)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0121");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0121.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/19/6");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20703");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail' package(s) announced via the MGASA-2017-0121 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squirrelmail version 1.4.22 (and probably prior) is vulnerable to a remote
code execution vulnerability because it fails to sanitize a string before
passing it to a popen call. It's possible to exploit this vulnerability to
execute arbitrary shell commands on the remote server (CVE-2017-7692).");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ar", rpm:"squirrelmail-ar~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-bg", rpm:"squirrelmail-bg~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-bn-bangladesh", rpm:"squirrelmail-bn-bangladesh~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-bn-india", rpm:"squirrelmail-bn-india~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ca", rpm:"squirrelmail-ca~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-cs", rpm:"squirrelmail-cs~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-cy", rpm:"squirrelmail-cy~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-cyrus", rpm:"squirrelmail-cyrus~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-da", rpm:"squirrelmail-da~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-de", rpm:"squirrelmail-de~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-el", rpm:"squirrelmail-el~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-es", rpm:"squirrelmail-es~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-et", rpm:"squirrelmail-et~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-eu", rpm:"squirrelmail-eu~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-fa", rpm:"squirrelmail-fa~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-fi", rpm:"squirrelmail-fi~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-fo", rpm:"squirrelmail-fo~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-fr", rpm:"squirrelmail-fr~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-fy", rpm:"squirrelmail-fy~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-he", rpm:"squirrelmail-he~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-hr", rpm:"squirrelmail-hr~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-hu", rpm:"squirrelmail-hu~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-id", rpm:"squirrelmail-id~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-is", rpm:"squirrelmail-is~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-it", rpm:"squirrelmail-it~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ja", rpm:"squirrelmail-ja~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ka", rpm:"squirrelmail-ka~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-km", rpm:"squirrelmail-km~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ko", rpm:"squirrelmail-ko~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-lt", rpm:"squirrelmail-lt~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-lv", rpm:"squirrelmail-lv~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-mk", rpm:"squirrelmail-mk~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ms", rpm:"squirrelmail-ms~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-nb", rpm:"squirrelmail-nb~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-nl", rpm:"squirrelmail-nl~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-nn", rpm:"squirrelmail-nn~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-pl", rpm:"squirrelmail-pl~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-poutils", rpm:"squirrelmail-poutils~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-pt", rpm:"squirrelmail-pt~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ro", rpm:"squirrelmail-ro~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ru", rpm:"squirrelmail-ru~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-sk", rpm:"squirrelmail-sk~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-sl", rpm:"squirrelmail-sl~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-sr", rpm:"squirrelmail-sr~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-sv", rpm:"squirrelmail-sv~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ta", rpm:"squirrelmail-ta~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-tr", rpm:"squirrelmail-tr~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-ug", rpm:"squirrelmail-ug~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-uk", rpm:"squirrelmail-uk~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-vi", rpm:"squirrelmail-vi~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-zh_CN", rpm:"squirrelmail-zh_CN~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail-zh_TW", rpm:"squirrelmail-zh_TW~1.4.22~12.2.mga5", rls:"MAGEIA5"))) {
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
