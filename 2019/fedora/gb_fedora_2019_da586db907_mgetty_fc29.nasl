# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.876016");
  script_version("2021-08-31T14:01:23+0000");
  script_cve_id("CVE-2018-16741", "CVE-2018-16744", "CVE-2018-16745");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-05-07 02:31:51 +0000 (Tue, 07 May 2019)");
  script_name("Fedora Update for mgetty FEDORA-2019-da586db907");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-da586db907");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2BKJH5L36K3KM5PSM6E7KXIKFZ7OEWAE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mgetty'
  package(s) announced via the FEDORA-2019-da586db907 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The mgetty package contains a 'smart' getty which allows logins over a
serial line (i.e., through a modem). If you&#39, re using a Class 2 or 2.0
modem, mgetty can receive faxes. If you also need to send faxes,
you&#39, ll need to install the sendfax program.

If you&#39, ll be dialing in to your system using a modem, you should
install the mgetty package. If you&#39, d like to send faxes using mgetty
and your modem, you&#39, ll need to install the mgetty-sendfax program. If
you need a viewer for faxes, you&#39, ll also need to install the
mgetty-viewfax package.");

  script_tag(name:"affected", value:"'mgetty' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"mgetty", rpm:"mgetty~1.1.37~11.fc29", rls:"FC29"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
