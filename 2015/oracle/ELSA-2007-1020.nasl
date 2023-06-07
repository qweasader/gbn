# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122647");
  script_cve_id("CVE-2007-4351");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:14 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T09:12:43+0000");
  script_tag(name:"last_modification", value:"2022-04-05 09:12:43 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2007-1020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-1020");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-1020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the ELSA-2007-1020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.4-11.14.el5_1.1]
 - Applied patch to fix CVE-2007-4351 (STR #2561, bug #353981).

 [1.2.4-11.14]
 - Applied patch to fix cupsd crash when failing to open a file: URI
 (STR #2351, bug #250415).

 [1.2.4-11.13]
 - Moved LSPP security attributes check before job creation (bug #231522).

 [1.2.4-11.12]
 - Moved LSPP access check before job creation (bug #231522).

 [1.2.4-11.11]
 - Better error checking in the LSPP patch (bug #231522).

 [1.2.4-11.10]
 - Applied patch to fix CVE-2007-3387 (bug #248223).

 [1.2.4-11.9]
 - Fixed IPv6 address parsing (bug #241400, STR #2117).
 - Fixed a bug that caused cups-lpd not to set the correct value for
 job-originating-host-name (bug #240223, STR #2023).
 - Cleaned up initscript error handling (bug #237953).
 - Fixed cups-lpd -odocument-format=... option (bug #230073, STR #2266).
 - Fixed If-Modified-Since: handling in libcups (bug #218764, STR #2133).
 - Make the initscript use start priority 56 (bug #213828).

 [1.2.4-11.8]
 - Applied fix for STR #2264 (bug #230118).
 - Added patch for UNIX domain sockets authentication (bug #230613).
 - LSPP: Updated patch for line-wrapped labels (bug #228107).

 [1.2.4-11.7]
 - Don't reload CUPS after rotating the logs with logrotate, but make sure
 to use the new file in that case (bug #215024).

 [1.2.4-11.6]
 - LSPP: added check_context() function for get_jobs(), get_job_attrs() and
 validate_user() (bug #229673).
 - Fixed a potential scheduler crash (bug #231522).");

  script_tag(name:"affected", value:"'cups' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.2.4~11.14.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.2.4~11.14.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.2.4~11.14.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.2.4~11.14.el5_1.1", rls:"OracleLinux5"))) {
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
