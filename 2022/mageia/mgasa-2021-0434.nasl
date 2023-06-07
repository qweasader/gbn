# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0434");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2021-0434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0434");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0434.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29449");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/K3JL66LCDUIASS4TM7SY6R2D7W2WBXUE/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2001690");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/1085");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd' package(s) announced via the MGASA-2021-0434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fixes memory disclosure to RADIUS servers by mod_radius.

Ftp clients like filezilla fail to detect locale with in log :
'Status: Server does not support non-ASCII characters.'

This comes from proftpd MultilineRFC2228 directive enabled by default.

Without this directive Filezilla is able to enable utf8 options
correctly.

Fixed by disabling MultilineRFC2228 directive.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_autohost", rpm:"proftpd-mod_autohost~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ban", rpm:"proftpd-mod_ban~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_case", rpm:"proftpd-mod_case~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ctrls_admin", rpm:"proftpd-mod_ctrls_admin~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ifsession", rpm:"proftpd-mod_ifsession~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ldap", rpm:"proftpd-mod_ldap~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_load", rpm:"proftpd-mod_load~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_memcache", rpm:"proftpd-mod_memcache~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab", rpm:"proftpd-mod_quotatab~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_file", rpm:"proftpd-mod_quotatab_file~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_ldap", rpm:"proftpd-mod_quotatab_ldap~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_radius", rpm:"proftpd-mod_quotatab_radius~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_sql", rpm:"proftpd-mod_quotatab_sql~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_radius", rpm:"proftpd-mod_radius~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ratio", rpm:"proftpd-mod_ratio~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_rewrite", rpm:"proftpd-mod_rewrite~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp", rpm:"proftpd-mod_sftp~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp_pam", rpm:"proftpd-mod_sftp_pam~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp_sql", rpm:"proftpd-mod_sftp_sql~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_shaper", rpm:"proftpd-mod_shaper~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_site_misc", rpm:"proftpd-mod_site_misc~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql", rpm:"proftpd-mod_sql~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_mysql", rpm:"proftpd-mod_sql_mysql~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_passwd", rpm:"proftpd-mod_sql_passwd~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_postgres", rpm:"proftpd-mod_sql_postgres~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_sqlite", rpm:"proftpd-mod_sql_sqlite~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls", rpm:"proftpd-mod_tls~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls_memcache", rpm:"proftpd-mod_tls_memcache~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls_shmcache", rpm:"proftpd-mod_tls_shmcache~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_unique_id", rpm:"proftpd-mod_unique_id~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_vroot", rpm:"proftpd-mod_vroot~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap", rpm:"proftpd-mod_wrap~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap_file", rpm:"proftpd-mod_wrap_file~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap_sql", rpm:"proftpd-mod_wrap_sql~1.3.7a~3.1.mga8", rls:"MAGEIA8"))) {
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
