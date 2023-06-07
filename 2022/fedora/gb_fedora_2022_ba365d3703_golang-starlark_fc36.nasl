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
  script_oid("1.3.6.1.4.1.25623.1.0.821813");
  script_version("2022-07-25T10:11:13+0000");
  script_cve_id("CVE-2022-1996", "CVE-2022-24675", "CVE-2022-28327", "CVE-2022-27191", "CVE-2022-29526", "CVE-2022-30629");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-07-25 10:11:13 +0000 (Mon, 25 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-07-14 01:15:49 +0000 (Thu, 14 Jul 2022)");
  script_name("Fedora: Security Advisory for golang-starlark (FEDORA-2022-ba365d3703)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-ba365d3703");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BL63HFXWBM2JI2X5BKC75DVWUQ7IQHFQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-starlark'
  package(s) announced via the FEDORA-2022-ba365d3703 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Starlark is a dialect of Python intended for use as a configuration language.
Like Python, it is an untyped dynamic language with high-level data types,
first-class functions with lexical scope, and garbage collection. Unlike
CPython, independent Starlark threads execute in parallel, so Starlark
workloads scale well on parallel machines. Starlark is a small and simple
language with a familiar and highly readable syntax. You can use it as an
expressive notation for structured data, defining functions to eliminate
repetition, or you can use it to add scripting capabilities to an existing
application.");

  script_tag(name:"affected", value:"'golang-starlark' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-starlark-0", rpm:"golang-starlark-0~0.7.20210113gite81fc95.fc36", rls:"FC36"))) {
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