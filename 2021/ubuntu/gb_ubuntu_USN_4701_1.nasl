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
  script_oid("1.3.6.1.4.1.25623.1.0.844796");
  script_cve_id("CVE-2020-16042", "CVE-2020-16044", "CVE-2020-26970", "CVE-2020-26971", "CVE-2020-26973", "CVE-2020-26974", "CVE-2020-26978", "CVE-2020-35111", "CVE-2020-35113");
  script_tag(name:"creation_date", value:"2021-01-21 04:00:27 +0000 (Thu, 21 Jan 2021)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-12 19:15:00 +0000 (Tue, 12 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4701-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.10");

  script_xref(name:"Advisory-ID", value:"USN-4701-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4701-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-4701-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, bypass the CSS sanitizer, or execute
arbitrary code. (CVE-2020-16042, CVE-2020-16044, CVE-2020-26971,
CVE-2020-26973, CVE-2020-26974, CVE-2020-26978, CVE-2020-35113)

It was discovered that the proxy.onRequest API did not catch
view-source URLs. If a user were tricked in to installing an
extension with the proxy permission and opening View Source, an
attacker could potentially exploit this to obtain sensitive
information. (CVE-2020-35111)

A stack overflow was discovered due to incorrect parsing of SMTP server
response codes. An attacker could potentially exploit this to execute
arbitrary code. (CVE-2020-26970)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 20.10.");

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

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:78.6.1+build1-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
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
