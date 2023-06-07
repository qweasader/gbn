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
  script_oid("1.3.6.1.4.1.25623.1.0.853718");
  script_version("2021-08-26T13:01:12+0000");
  script_cve_id("CVE-2021-26813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-10 03:15:00 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:01:33 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for python-markdown2 (openSUSE-SU-2021:0429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0429-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3VPKRS46KKKFGLEDJJ7ZX2EZVNE5567H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-markdown2'
  package(s) announced via the openSUSE-SU-2021:0429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-markdown2 fixes the following issues:

     Update to 2.4.0 (boo#1181270):

  - [pull #377] Fixed bug breaking strings elements in metadata lists

  - [pull #380] When rendering fenced code blocks, also add the
         language-LANG class

  - [pull #387] Regex DoS fixes (CVE-2021-26813, boo#1183171)

  - Switch off failing tests (gh#trentm/python-markdown2#388), ignore
       failing test suite.

     update to 2.3.9:

  - [pull #335] Added header support for wiki tables

  - [pull #336] Reset _toc when convert is run

  - [pull #353] XSS fix

  - [pull #350] XSS fix

  - Add patch to fix unsanitized input for cross-site scripting (boo#1171379)");

  script_tag(name:"affected", value:"'python-markdown2' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"python2-markdown2", rpm:"python2-markdown2~2.4.0~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-markdown2", rpm:"python3-markdown2~2.4.0~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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