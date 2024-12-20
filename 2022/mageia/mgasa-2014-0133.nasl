# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0133");
  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-17 13:52:26 +0000 (Mon, 17 Mar 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0133");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0133.html");
  script_xref(name:"URL", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/03/12/12");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13003");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lighttpd' package(s) announced via the MGASA-2014-0133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SQL injection vulnerability in lighttpd before 1.4.35 when
mod_mysql_vhost is in use, due to insufficient validation of hostnames in
HTTP requests (CVE-2014-2323).

Possible path traversal vulnerabilities in lighttpd before 1.4.35 when
either mod_evhost or mod_simple_vhost are in use, due to insufficient
validation of hostnames in HTTP requests (CVE-2014-2324).");

  script_tag(name:"affected", value:"'lighttpd' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_auth", rpm:"lighttpd-mod_auth~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_cml", rpm:"lighttpd-mod_cml~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_compress", rpm:"lighttpd-mod_compress~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_mysql_vhost", rpm:"lighttpd-mod_mysql_vhost~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_trigger_b4_dl", rpm:"lighttpd-mod_trigger_b4_dl~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.32~3.7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_auth", rpm:"lighttpd-mod_auth~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_cml", rpm:"lighttpd-mod_cml~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_compress", rpm:"lighttpd-mod_compress~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_geoip", rpm:"lighttpd-mod_geoip~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_mysql_vhost", rpm:"lighttpd-mod_mysql_vhost~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_trigger_b4_dl", rpm:"lighttpd-mod_trigger_b4_dl~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.33~4.1.mga4", rls:"MAGEIA4"))) {
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
