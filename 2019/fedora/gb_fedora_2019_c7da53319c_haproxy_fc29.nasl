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
  script_oid("1.3.6.1.4.1.25623.1.0.876055");
  script_version("2021-09-02T08:01:23+0000");
  script_cve_id("CVE-2018-20615", "CVE-2018-20103", "CVE-2018-20102");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-25 12:57:00 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-05-07 02:33:18 +0000 (Tue, 07 May 2019)");
  script_name("Fedora Update for haproxy FEDORA-2019-c7da53319c");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-c7da53319c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7TWGMJJTAJCLODPCSCHJD3JC5WZTWPCS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the FEDORA-2019-c7da53319c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HAProxy is a TCP/HTTP reverse proxy which is particularly suited for high
availability environments. Indeed, it can:

  - route HTTP requests depending on statically assigned cookies

  - spread load among several servers while assuring server persistence
   through the use of HTTP cookies

  - switch to backup servers in the event a main one fails

  - accept connections to special ports dedicated to service monitoring

  - stop accepting connections without breaking existing ones

  - add, modify, and delete HTTP headers in both directions

  - block requests matching particular patterns

  - report detailed status to authenticated users from a URI
   intercepted from the application");

  script_tag(name:"affected", value:"'haproxy' package(s) on Fedora 29.");

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

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.8.17~1.fc29", rls:"FC29"))) {
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
