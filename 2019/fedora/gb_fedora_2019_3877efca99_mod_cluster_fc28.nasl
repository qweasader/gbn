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
  script_oid("1.3.6.1.4.1.25623.1.0.876338");
  script_version("2021-09-02T10:01:39+0000");
  script_cve_id("CVE-2016-8612", "CVE-2016-3110");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 15:34:00 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-10 02:11:25 +0000 (Fri, 10 May 2019)");
  script_name("Fedora Update for mod_cluster FEDORA-2019-3877efca99");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC28");

  script_xref(name:"FEDORA", value:"2019-3877efca99");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CX5QNNIVAUB2VVDV6TR3YMFTL6VRKOBO");

  script_tag(name:"summary", value:"The remote host is missing an update for
  the 'mod_cluster' package(s) announced via the FEDORA-2019-3877efca99 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"Mod_cluster is an httpd-based load balancer.
  Like mod_jk and mod_proxy, mod_cluster uses a communication channel to forward
  requests from httpd to one of a set of application server nodes. Unlike mod_jk
  and mod_proxy, mod_cluster leverages an additional connection between the
  application server nodes and httpd. The application server nodes use this
  connection to transmit server-side load balance factors and lifecycle events
  back to httpd via a custom set of HTTP methods, affectionately called the
  Mod-Cluster Management Protocol (MCMP). This additional feedback channel
  allows mod_cluster to offer a level of intelligence and granularity not
  found in other load balancing solutions.");

  script_tag(name:"affected", value:"'mod_cluster' package(s) on Fedora 28.");

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

if(release == "FC28") {

  if(!isnull(res = isrpmvuln(pkg:"mod_cluster", rpm:"mod_cluster~1.3.11~1.fc28", rls:"FC28"))) {
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
