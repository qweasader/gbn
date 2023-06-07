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
  script_oid("1.3.6.1.4.1.25623.1.0.876949");
  script_version("2021-09-01T14:01:32+0000");
  script_cve_id("CVE-2017-16808", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14466", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14465", "CVE-2018-14881", "CVE-2018-14464", "CVE-2018-14463", "CVE-2018-14467", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14880", "CVE-2018-16451", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16229", "CVE-2018-16301", "CVE-2018-16230", "CVE-2018-16452", "CVE-2018-16300", "CVE-2018-16228", "CVE-2019-15166", "CVE-2019-15167", "CVE-2018-19519", "CVE-2018-14879", "CVE-2019-1010220");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-11 23:15:00 +0000 (Fri, 11 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-30 03:35:05 +0000 (Wed, 30 Oct 2019)");
  script_name("Fedora Update for tcpdump FEDORA-2019-d06bc63433");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-d06bc63433");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FNYXF3IY2X65IOD422SA6EQUULSGW7FN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump'
  package(s) announced via the FEDORA-2019-d06bc63433 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tcpdump is a command-line tool for monitoring network traffic.
Tcpdump can capture and display the packet headers on a particular
network interface or on all interfaces.  Tcpdump can display all of
the packet headers, or just the ones that match particular criteria.

Install tcpdump if you need a program to monitor network traffic.");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Fedora 30.");

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

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.3~1.fc30", rls:"FC30"))) {
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