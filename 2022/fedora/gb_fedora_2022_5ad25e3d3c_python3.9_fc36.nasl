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
  script_oid("1.3.6.1.4.1.25623.1.0.820757");
  script_version("2022-11-15T10:10:43+0000");
  script_cve_id("CVE-2015-20107");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"last_modification", value:"2022-11-15 10:10:43 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:00 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-06-19 01:11:47 +0000 (Sun, 19 Jun 2022)");
  script_name("Fedora: Security Advisory for python3.9 (FEDORA-2022-5ad25e3d3c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-5ad25e3d3c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FCIO2W4DUVVMI6L52QCC4TT2B3K5VWHS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.9'
  package(s) announced via the FEDORA-2022-5ad25e3d3c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.9 package for developers.

This package exists to allow developers to test their code against an older
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.9, see other distributions
that support it, such as CentOS or RHEL or older Fedora releases.");

  script_tag(name:"affected", value:"'python3.9' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"python3.9", rpm:"python3.9~3.9.13~2.fc36", rls:"FC36"))) {
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