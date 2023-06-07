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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0356");
  script_cve_id("CVE-2013-4522", "CVE-2013-4523", "CVE-2013-4524", "CVE-2013-4525");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0356");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0356.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11671");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=244479");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=244480");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=244481");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=244482");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.4.7_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=243213");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2013-0356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some files were being delivered with incorrect headers in Moodle before
2.4.7, meaning they could be cached downstream (CVE-2013-4522).

Cross-site scripting in Moodle before 2.4.7 due to JavaScript in messages
being executed on some pages (CVE-2013-4523).

The file system repository in Moodle before 2.4.7 was allowing access to
files beyond the Moodle file area (CVE-2013-4524).

Cross-site scripting in Moodle before 2.4. due to JavaScript in question
answers being executed on the Quiz Results page (CVE-2013-4525).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.7~1.mga3", rls:"MAGEIA3"))) {
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
