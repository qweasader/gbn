# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842091");
  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");
  script_tag(name:"creation_date", value:"2015-02-12 04:28:16 +0000 (Thu, 12 Feb 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 20:18:00 +0000 (Fri, 31 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-2499-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2499-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2499-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.4, postgresql-9.1, postgresql-9.3, postgresql-9.4' package(s) announced via the USN-2499-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephen Frost discovered that PostgreSQL incorrectly displayed certain
values in error messages. An authenticated user could gain access to seeing
certain values, contrary to expected permissions. (CVE-2014-8161)

Andres Freund, Peter Geoghegan and Noah Misch discovered that PostgreSQL
incorrectly handled buffers in to_char functions. An authenticated attacker
could possibly use this issue to cause PostgreSQL to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2015-0241)

It was discovered that PostgreSQL incorrectly handled memory in the
pgcrypto extension. An authenticated attacker could possibly use this issue
to cause PostgreSQL to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2015-0243)

Emil Lenngren discovered that PostgreSQL incorrectly handled extended
protocol message reading. An authenticated attacker could possibly use this
issue to cause PostgreSQL to crash, resulting in a denial of service, or
possibly inject query messages. (CVE-2015-0244)");

  script_tag(name:"affected", value:"'postgresql-8.4, postgresql-9.1, postgresql-9.3, postgresql-9.4' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.22-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.15-0ubuntu0.12.04", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.3", ver:"9.3.6-0ubuntu0.14.04", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.4", ver:"9.4.1-0ubuntu0.14.10", rls:"UBUNTU14.10"))) {
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