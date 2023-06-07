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
  script_oid("1.3.6.1.4.1.25623.1.0.131214");
  script_cve_id("CVE-2015-8688");
  script_tag(name:"creation_date", value:"2016-02-08 17:55:20 +0000 (Mon, 08 Feb 2016)");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:29:00 +0000 (Wed, 07 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0046");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0046.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17474");
  script_xref(name:"URL", value:"http://gultsch.de/gajim_roster_push_and_message_interception.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gajim, python-nbxmpp' package(s) announced via the MGASA-2016-0046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gajim before 0.16.5 doesn't verify the origin of roster pushes thus
allowing third parties to modify the roster via a man-in-the-middle attack
(CVE-2015-8688).");

  script_tag(name:"affected", value:"'gajim, python-nbxmpp' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gajim", rpm:"gajim~0.16.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-nbxmpp", rpm:"python-nbxmpp~0.5.3~1.mga5", rls:"MAGEIA5"))) {
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
