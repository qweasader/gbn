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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0018");
  script_cve_id("CVE-2017-5193", "CVE-2017-5194", "CVE-2017-5195", "CVE-2017-5196", "CVE-2017-5356");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-15 19:32:00 +0000 (Fri, 15 Mar 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0018");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0018.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20078");
  script_xref(name:"URL", value:"https://irssi.org/security/irssi_sa_2017_01.txt");
  script_xref(name:"URL", value:"https://irssi.org/2017/01/05/irssi-0.8.21-released/");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/01/13/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi' package(s) announced via the MGASA-2017-0018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In irssi before 0.8.21, a NULL pointer dereference in the nickcmp
function (CVE-2017-5193).

In irssi before 0.8.21, use after free when receiving invalid nick
message (CVE-2017-5194).

In irssi before 0.8.21, out of bounds read in certain incomplete control
codes (CVE-2017-5195).

In irssi before 0.8.21, out of bounds read in certain incomplete
character sequences (CVE-2017-5196).

In irssi before 0.8.21, out of bounds read when printing certain values
(CVE-2017-5356).");

  script_tag(name:"affected", value:"'irssi' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.21~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-devel", rpm:"irssi-devel~0.8.21~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-perl", rpm:"irssi-perl~0.8.21~1.mga5", rls:"MAGEIA5"))) {
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
