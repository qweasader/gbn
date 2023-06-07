# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.878758");
  script_version("2021-07-16T02:00:53+0000");
  script_cve_id("CVE-2020-27837");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-30 15:26:00 +0000 (Wed, 30 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-22 04:13:18 +0000 (Tue, 22 Dec 2020)");
  script_name("Fedora: Security Advisory for gdm (FEDORA-2020-1650d8012f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"FEDORA", value:"2020-1650d8012f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M5RID2Q5MGAY5G7LQE6VGDEEN36NWDTO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm'
  package(s) announced via the FEDORA-2020-1650d8012f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GDM, the GNOME Display Manager, handles authentication-related backend
functionality for logging in a user and unlocking the user&#39, s session after
it&#39, s been locked. GDM also provides functionality for initiating user-switching,
so more than one user can be logged in at the same time. It handles
graphical session registration with the system for both local and remote
sessions (in the latter case, via the XDMCP protocol).  In cases where the
session doesn&#39, t provide it&#39, s own display server, GDM can start the display
server on behalf of the session.");

  script_tag(name:"affected", value:"'gdm' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"gdm", rpm:"gdm~3.38.2.1~1.fc33", rls:"FC33"))) {
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