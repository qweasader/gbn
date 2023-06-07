# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.843027");
  script_cve_id("CVE-2016-9893", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9904", "CVE-2016-9905", "CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396");
  script_tag(name:"creation_date", value:"2017-01-28 04:41:18 +0000 (Sat, 28 Jan 2017)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:54:00 +0000 (Thu, 02 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3165-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3165-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-3165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-9893, CVE-2017-5373)

Andrew Krasichkov discovered that event handlers on <marquee> elements
were executed despite a Content Security Policy (CSP) that disallowed
inline JavaScript. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2016-9895)

A memory corruption issue was discovered in WebGL in some circumstances.
If a user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-9897)

A use-after-free was discovered when manipulating DOM subtrees in the
Editor. If a user were tricked in to opening a specially crafted website
in a browsing context, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-9898)

A use-after-free was discovered when manipulating DOM events and audio
elements. If a user were tricked in to opening a specially crafted website
in a browsing context, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-9899)

It was discovered that external resources that should be blocked when
loading SVG images can bypass security restrictions using data: URLs. An
attacker could potentially exploit this to obtain sensitive information.
(CVE-2016-9900)

Jann Horn discovered that JavaScript Map/Set were vulnerable to timing
attacks. If a user were tricked in to opening a specially crafted website
in a browsing context, an attacker could potentially exploit this to
obtain sensitive information across domains. (CVE-2016-9904)

A crash was discovered in EnumerateSubDocuments while adding or removing
sub-documents. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit this
to execute arbitrary code. (CVE-2016-9905)

JIT code allocation can allow a bypass of ASLR protections in some
circumstances. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute arbitrary
code. (CVE-2017-5375)

Nicolas Gregoire discovered a use-after-free when manipulating XSL in
XSLT documents in some circumstances. If a user were tricked in to opening
a specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.7.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.7.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.7.0+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.7.0+build1-0ubuntu0.16.10.1", rls:"UBUNTU16.10"))) {
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
