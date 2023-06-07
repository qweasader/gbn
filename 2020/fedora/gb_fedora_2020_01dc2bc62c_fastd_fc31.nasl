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
  script_oid("1.3.6.1.4.1.25623.1.0.878556");
  script_version("2021-07-21T02:01:11+0000");
  script_cve_id("CVE-2020-27638");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-03 03:15:00 +0000 (Tue, 03 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-03 04:24:01 +0000 (Tue, 03 Nov 2020)");
  script_name("Fedora: Security Advisory for fastd (FEDORA-2020-01dc2bc62c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-01dc2bc62c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WSMH65GHKHMJAK2VMPROIPIUS4IA63CW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fastd'
  package(s) announced via the FEDORA-2020-01dc2bc62c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fastd is a secure tunneling daemon with some unique features:

  - Very small binary (about 100KB on OpenWRT in the default configuration,
   including all dependencies besides libc)

  - Exchangeable crypto methods

  - Transport over UDP for simple usage behind NAT

  - Can run in 1:1 and 1:n scenarios

  - There are no server and client roles defined by the protocol, this is just
   defined by the usage.

  - Only one instance of the daemon is needed on each host to create a full mesh
   If no full mesh is established, a routing protocol is necessary to enable
   hosts that are not connected directly to reach each other");

  script_tag(name:"affected", value:"'fastd' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"fastd", rpm:"fastd~21~1.fc31", rls:"FC31"))) {
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
