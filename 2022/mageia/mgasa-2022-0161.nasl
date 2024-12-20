# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0161");
  script_cve_id("CVE-2022-22707");
  script_tag(name:"creation_date", value:"2022-05-09 04:28:10 +0000 (Mon, 09 May 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-13 20:52:29 +0000 (Thu, 13 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0161)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0161");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0161.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29877");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6P5G6MJW4Q5RKKPO7TS5CLAAEQ2QUYBE/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5040");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lighttpd' package(s) announced via the MGASA-2022-0161 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In lighttpd 1.4.46 through 1.4.63, the mod_extforward_Forwarded function
of the mod_extforward plugin has a stack-based buffer overflow (4 bytes
representing -1), as demonstrated by remote denial of service (daemon
crash) in a non-default configuration. The non-default configuration
requires handling of the Forwarded header in a somewhat unusual manner.
Also, a 32-bit system is much more likely to be affected than a 64-bit
system. (CVE-2022-22707)");

  script_tag(name:"affected", value:"'lighttpd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_ajp13", rpm:"lighttpd-mod_ajp13~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_auth", rpm:"lighttpd-mod_auth~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_file", rpm:"lighttpd-mod_authn_file~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap", rpm:"lighttpd-mod_authn_ldap~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_mysql", rpm:"lighttpd-mod_authn_mysql~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_cml", rpm:"lighttpd-mod_cml~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_deflate", rpm:"lighttpd-mod_deflate~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_geoip", rpm:"lighttpd-mod_geoip~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_mysql_vhost", rpm:"lighttpd-mod_mysql_vhost~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_trigger_b4_dl", rpm:"lighttpd-mod_trigger_b4_dl~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_uploadprogress", rpm:"lighttpd-mod_uploadprogress~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.59~1.1.mga8", rls:"MAGEIA8"))) {
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
