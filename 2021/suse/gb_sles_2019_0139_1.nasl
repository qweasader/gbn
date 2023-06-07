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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0139.1");
  script_cve_id("CVE-2016-9015");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:31 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-13 13:09:00 +0000 (Fri, 13 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0139-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190139-1/");
  script_xref(name:"URL", value:"https://github.com/Lukasa/urllib3/blob/1.22/CHANGES.rst");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-urllib3' package(s) announced via the SUSE-SU-2019:0139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-urllib3 fixes the following issues:

python-urllib3 was updated to version 1.22 (fate#326733, bsc#1110422) and contains new features and lots of bugfixes:

The full changelog can be found on:

 [link moved to references]

Security issues fixed:
CVE-2016-9015: TLS certificate validation vulnerability (bsc#1024540).
 (This issue did not affect our previous version 1.16.)

Non security issues fixed:
bsc#1074247: Fix test suite, use correct date (gh#shazow/urllib3#1303).");

  script_tag(name:"affected", value:"'python-urllib3' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Enterprise Storage 4, SUSE Enterprise Storage 5, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Manager Server 3.1, SUSE Manager Server 3.2.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.22~3.10.1", rls:"SLES12.0"))) {
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
