# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840116");
  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6505", "CVE-2006-6506");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-400-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.10|6\.06\ LTS|6\.10)");

  script_xref(name:"Advisory-ID", value:"USN-400-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-400-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird' package(s) announced via the USN-400-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Georgi Guninski and David Bienvenu discovered that long Content-Type and
RFC2047-encoded headers we vulnerable to heap overflows. By tricking
the user into opening a specially crafted email, an attacker could
execute arbitrary code with user privileges. (CVE-2006-6506)

Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges or bypass internal XSS protections
by tricking the user into opening a malicious email containing
JavaScript. Please note that JavaScript is disabled by default for
emails, and it is not recommended to enable it. (CVE-2006-6497,
CVE-2006-6498, CVE-2006-6499, CVE-2006-6501, CVE-2006-6502,
CVE-2006-6503)");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.9-0ubuntu0.5.10", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.9-0ubuntu0.5.10", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.9-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.9-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.9-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.9-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
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
