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
  script_oid("1.3.6.1.4.1.25623.1.0.879444");
  script_version("2021-08-20T12:01:13+0000");
  script_cve_id("CVE-2021-3426");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-20 12:01:13 +0000 (Fri, 20 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-04-25 03:09:23 +0000 (Sun, 25 Apr 2021)");
  script_name("Fedora: Security Advisory for python3-docs (FEDORA-2021-0a8f3ffbc0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-0a8f3ffbc0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3XX4GPMLHEZMPOIHB3GVF5ASEN337M7N");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3-docs'
  package(s) announced via the FEDORA-2021-0a8f3ffbc0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The python3-docs package contains documentation on the Python 3
programming language and interpreter.");

  script_tag(name:"affected", value:"'python3-docs' package(s) on Fedora 34.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.9.4~1.fc34", rls:"FC34"))) {
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