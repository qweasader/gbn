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
  script_oid("1.3.6.1.4.1.25623.1.0.822318");
  script_version("2022-08-10T10:11:40+0000");
  script_cve_id("CVE-2022-31116", "CVE-2022-31117", "CVE-2021-45958");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-14 11:32:00 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-08-04 01:12:28 +0000 (Thu, 04 Aug 2022)");
  script_name("Fedora: Security Advisory for python-ujson (FEDORA-2022-33e816bc37)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-33e816bc37");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NAU5N4A7EUK2AMUCOLYDD5ARXAJYZBD2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-ujson'
  package(s) announced via the FEDORA-2022-33e816bc37 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"UltraJSON is an ultra fast JSON encoder and decoder written in pure C with
bindings for Python.");

  script_tag(name:"affected", value:"'python-ujson' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"python-ujson", rpm:"python-ujson~5.4.0~1.fc35", rls:"FC35"))) {
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