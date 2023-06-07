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
  script_oid("1.3.6.1.4.1.25623.1.0.879742");
  script_version("2021-08-24T06:00:58+0000");
  script_cve_id("CVE-2021-32642");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-24 06:00:58 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 13:20:00 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 03:24:38 +0000 (Thu, 17 Jun 2021)");
  script_name("Fedora: Security Advisory for radsecproxy (FEDORA-2021-a4be4c93e4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-a4be4c93e4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HOC5AFG65NYLMMUTNSBOPC5F4LBAC7BR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radsecproxy'
  package(s) announced via the FEDORA-2021-a4be4c93e4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"radsecproxy is a generic RADIUS proxy that in addition to usual RADIUS UDP
transport, also supports TLS (RadSec), as well as RADIUS over TCP and DTLS.
The aim is for the proxy to have sufficient features to be flexible, while
at the same time to be small, efficient and easy to configure.");

  script_tag(name:"affected", value:"'radsecproxy' package(s) on Fedora 33.");

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

  if(!isnull(res = isrpmvuln(pkg:"radsecproxy", rpm:"radsecproxy~1.9.0~1.fc33", rls:"FC33"))) {
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