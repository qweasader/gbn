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
  script_oid("1.3.6.1.4.1.25623.1.0.879633");
  script_version("2021-08-23T12:01:00+0000");
  script_cve_id("CVE-2021-31800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 13:10:00 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-20 04:54:10 +0000 (Thu, 20 May 2021)");
  script_name("Fedora: Security Advisory for python-impacket (FEDORA-2021-52dfb60726)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-52dfb60726");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UF56LYB27LHEIFJTFHU3M75NMNNK2SCG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-impacket'
  package(s) announced via the FEDORA-2021-52dfb60726 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Impacket is a collection of Python classes focused on providing access to
network packets. Impacket allows Python developers to craft and decode network
packets in simple and consistent manner. It is highly effective when used in
conjunction with a packet capture utility or package such as Pcapy. Packets
can be constructed from scratch, as well as parsed from raw data. Furthermore,
the object oriented API makes it simple to work with deep protocol hierarchies.");

  script_tag(name:"affected", value:"'python-impacket' package(s) on Fedora 34.");

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

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"python-impacket", rpm:"python-impacket~0.9.22~3.fc34", rls:"FC34"))) {
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