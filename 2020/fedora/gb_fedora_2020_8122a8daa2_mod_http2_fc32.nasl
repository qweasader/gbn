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
  script_oid("1.3.6.1.4.1.25623.1.0.878220");
  script_version("2021-07-19T11:00:51+0000");
  script_cve_id("CVE-2020-11993", "CVE-2020-9490");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2020-08-25 03:23:22 +0000 (Tue, 25 Aug 2020)");
  script_name("Fedora: Security Advisory for mod_http2 (FEDORA-2020-8122a8daa2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-8122a8daa2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4NKWG2EXAQQB6LMLATKZ7KLSRGCSHVAN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_http2'
  package(s) announced via the FEDORA-2020-8122a8daa2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The mod_h2 Apache httpd module implements the HTTP2 protocol (h2+h2c) on
top of libnghttp2 for httpd 2.4 servers.");

  script_tag(name:"affected", value:"'mod_http2' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"mod_http2", rpm:"mod_http2~1.15.14~1.fc32", rls:"FC32"))) {
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