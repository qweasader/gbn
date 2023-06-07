# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2162.1");
  script_cve_id("CVE-2017-18248", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-4182", "CVE-2018-4183");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2162-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182162-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the SUSE-SU-2018:2162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:
The following security vulnerabilities were fixed:
- CVE-2017-18248: Handle invalid characters properly in printing jobs.
 This fixes a problem that was causing the DBUS library to abort the
 calling process. (bsc#1061066 bsc#1087018)
- Fixed a local privilege escalation to root and sandbox bypasses in the
 scheduler
- CVE-2018-4180: Fixed a local privilege escalation to root in dnssd
 backend (bsc#1096405)
- CVE-2018-4181: Limited local file reads as root via cupsd.conf include
 directive (bsc#1096406)
- CVE-2018-4182: Fixed a sandbox bypass due to insecure error handling
 (bsc#1096407)
- CVE-2018-4183: Fixed a sandbox bypass due to profile misconfiguration
 (bsc#1096408)
The following other issue was fixed:
- Fixed authorization check for clients (like samba) connected through the
 local socket when Kerberos authentication is enabled (bsc#1050082)");

  script_tag(name:"affected", value:"'cups' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo", rpm:"cups-libs-debuginfo~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo-32bit", rpm:"cups-libs-debuginfo-32bit~1.7.5~20.14.1", rls:"SLES12.0SP3"))) {
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
