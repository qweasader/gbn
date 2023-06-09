# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851709");
  script_version("2021-06-28T11:00:33+0000");
  script_tag(name:"last_modification", value:"2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-23 09:06:11 +0100 (Fri, 23 Feb 2018)");
  script_cve_id("CVE-2017-15098", "CVE-2017-15099", "CVE-2017-7546", "CVE-2017-7547",
                "CVE-2017-7548", "CVE-2018-1053");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for postgresql95 (openSUSE-SU-2018:0529-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql95'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql95 fixes the following issues:

  Update to PostgreSQL 9.5.11:

  Security issues fixed:

  * CVE-2018-1053, boo#1077983: Ensure that all temporary files made by
  pg_upgrade are non-world-readable.

  * boo#1079757: Rename pg_rewind's copy_file_range function to avoid
  conflict with new Linux system call of that name.

  In version 9.5.10:

  * CVE-2017-15098, boo#1067844: Memory disclosure in JSON functions.

  * CVE-2017-15099, boo#1067841: INSERT ... ON CONFLICT DO UPDATE fails to
  enforce SELECT privileges.

  In version 9.5.9:

  * Show foreign tables in information_schema.table_privileges view.

  * Clean up handling of a fatal exit (e.g., due to receipt of SIGTERM)
  that occurs while trying to execute a ROLLBACK of a failed transaction.

  * Remove assertion that could trigger during a fatal exit.

  * Correctly identify columns that are of a range type or domain type
  over a composite type or domain type being searched for.

  * Fix crash in pg_restore when using parallel mode and using a list file
  to select a subset of items to restore.

  * Change ecpg's parser to allow RETURNING clauses without attached C
  variables.

  In version 9.5.8

  * CVE-2017-7547, boo#1051685: Further restrict visibility of
  pg_user_mappings.umoptions, to protect passwords stored as user
  mapping options.

  * CVE-2017-7546, boo#1051684: Disallow empty passwords in all
  password-based authentication methods.

  * CVE-2017-7548, boo#1053259: lo_put() function ignores ACLs.");

  script_tag(name:"affected", value:"postgresql95 on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0529-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-02/msg00042.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"postgresql95", rpm:"postgresql95~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-contrib", rpm:"postgresql95-contrib~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-contrib-debuginfo", rpm:"postgresql95-contrib-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-debuginfo", rpm:"postgresql95-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-debugsource", rpm:"postgresql95-debugsource~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-devel", rpm:"postgresql95-devel~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-devel-debuginfo", rpm:"postgresql95-devel-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-libs-debugsource", rpm:"postgresql95-libs-debugsource~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-plperl", rpm:"postgresql95-plperl~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-plperl-debuginfo", rpm:"postgresql95-plperl-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-plpython", rpm:"postgresql95-plpython~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-plpython-debuginfo", rpm:"postgresql95-plpython-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-pltcl", rpm:"postgresql95-pltcl~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-pltcl-debuginfo", rpm:"postgresql95-pltcl-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-server", rpm:"postgresql95-server~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-server-debuginfo", rpm:"postgresql95-server-debuginfo~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-test", rpm:"postgresql95-test~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql95-docs", rpm:"postgresql95-docs~9.5.11~2.3.1", rls:"openSUSELeap42.3"))) {
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
