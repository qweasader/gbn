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
  script_oid("1.3.6.1.4.1.25623.1.0.876545");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2017-18219", "CVE-2017-18220", "CVE-2018-6799", "CVE-2017-14504", "CVE-2017-14649", "CVE-2017-14733", "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15238", "CVE-2017-15930", "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-17498", "CVE-2017-17500", "CVE-2017-17501", "CVE-2017-17502", "CVE-2017-17503", "CVE-2017-11638", "CVE-2017-11642", "CVE-2017-11722", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13648", "CVE-2017-13736", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-12805", "CVE-2017-12806", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11474", "CVE-2019-11473");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 02:15:00 +0000 (Wed, 19 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-01 02:10:17 +0000 (Mon, 01 Jul 2019)");
  script_name("Fedora Update for GraphicsMagick FEDORA-2019-da4c20882c");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-da4c20882c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PF62B5PJA2JDUOCKJGUQO3SPL74BEYSV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the FEDORA-2019-da4c20882c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick is a comprehensive image processing package which is initially
based on ImageMagick 5.5.2, but which has undergone significant re-work by
the GraphicsMagick Group to significantly improve the quality and performance
of the software.");

  script_tag(name:"affected", value:"'GraphicsMagick' package(s) on Fedora 30.");

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

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.32~1.fc30", rls:"FC30"))) {
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
