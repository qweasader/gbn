# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0115");
  script_cve_id("CVE-2017-7418");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-11 19:35:58 +0000 (Tue, 11 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0115)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0115");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0115.html");
  script_xref(name:"URL", value:"http://www.proftpd.org/docs/RELEASE_NOTES-1.3.5e");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20640");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd' package(s) announced via the MGASA-2017-0115 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ProFTPD before 1.3.5e controls whether the home directory of a user could
contain a symbolic link through the AllowChrootSymlinks configuration
option, but checks only the last path component when enforcing
AllowChrootSymlinks. Attackers with local access could bypass the
AllowChrootSymlinks control by replacing a path component (other than the
last one) with a symbolic link. The threat model includes an attacker who
is not granted full filesystem access by a hosting provider, but can
reconfigure the home directory of an FTP user (CVE-2017-7418).");

  script_tag(name:"affected", value:"'proftpd' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_autohost", rpm:"proftpd-mod_autohost~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ban", rpm:"proftpd-mod_ban~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_case", rpm:"proftpd-mod_case~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ctrls_admin", rpm:"proftpd-mod_ctrls_admin~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_gss", rpm:"proftpd-mod_gss~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ifsession", rpm:"proftpd-mod_ifsession~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ldap", rpm:"proftpd-mod_ldap~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_load", rpm:"proftpd-mod_load~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_memcache", rpm:"proftpd-mod_memcache~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab", rpm:"proftpd-mod_quotatab~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_file", rpm:"proftpd-mod_quotatab_file~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_ldap", rpm:"proftpd-mod_quotatab_ldap~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_radius", rpm:"proftpd-mod_quotatab_radius~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_sql", rpm:"proftpd-mod_quotatab_sql~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_radius", rpm:"proftpd-mod_radius~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ratio", rpm:"proftpd-mod_ratio~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_rewrite", rpm:"proftpd-mod_rewrite~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp", rpm:"proftpd-mod_sftp~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp_pam", rpm:"proftpd-mod_sftp_pam~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp_sql", rpm:"proftpd-mod_sftp_sql~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_shaper", rpm:"proftpd-mod_shaper~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_site_misc", rpm:"proftpd-mod_site_misc~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql", rpm:"proftpd-mod_sql~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_mysql", rpm:"proftpd-mod_sql_mysql~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_passwd", rpm:"proftpd-mod_sql_passwd~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_postgres", rpm:"proftpd-mod_sql_postgres~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_sqlite", rpm:"proftpd-mod_sql_sqlite~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls", rpm:"proftpd-mod_tls~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls_memcache", rpm:"proftpd-mod_tls_memcache~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls_shmcache", rpm:"proftpd-mod_tls_shmcache~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_vroot", rpm:"proftpd-mod_vroot~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap", rpm:"proftpd-mod_wrap~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap_file", rpm:"proftpd-mod_wrap_file~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap_sql", rpm:"proftpd-mod_wrap_sql~1.3.5e~1.mga5", rls:"MAGEIA5"))) {
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
