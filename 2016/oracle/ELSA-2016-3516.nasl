# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122877");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:20 +0000 (Thu, 18 Feb 2016)");
  script_version("2022-03-17T16:04:20+0000");
  script_tag(name:"last_modification", value:"2022-03-17 16:04:20 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)");

  script_name("Oracle: Security Advisory (ELSA-2016-3516)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-3516");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-3516.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the ELSA-2016-3516 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.12-1.166.7]
- Update fix for CVE-2015-7547 (#1296028).

[2.12-1.166.6]
- Create helper threads with enough stack for POSIX AIO and timers (#1301625).

[2.12-1.166.5]
- Fix CVE-2015-7547: getaddrinfo() stack-based buffer overflow (#1296028).

[2.12-1.166.4]
- Support loading more libraries with static TLS (#1291270).");

  script_tag(name:"affected", value:"'glibc' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.166.ksplice1.el6_7.7", rls:"OracleLinux6"))) {
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
