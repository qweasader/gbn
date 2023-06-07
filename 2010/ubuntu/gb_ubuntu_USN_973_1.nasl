# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840481");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_tag(name:"creation_date", value:"2010-08-20 12:57:11 +0000 (Fri, 20 Aug 2010)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-973-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.04");

  script_xref(name:"Advisory-ID", value:"USN-973-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-973-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'koffice' package(s) announced via the USN-973-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Will Dormann, Alin Rad Pop, Braden Thomas, and Drew Yao discovered that the
Xpdf used in KOffice contained multiple security issues in its JBIG2
decoder. If a user or automated system were tricked into opening a crafted
PDF file, an attacker could cause a denial of service or execute arbitrary
code with privileges of the user invoking the program. (CVE-2009-0146,
CVE-2009-0147, CVE-2009-0166, CVE-2009-0799, CVE-2009-0800, CVE-2009-1179,
CVE-2009-1180, CVE-2009-1181)

It was discovered that the Xpdf used in KOffice contained multiple security
issues when parsing malformed PDF documents. If a user or automated system
were tricked into opening a crafted PDF file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the user
invoking the program. (CVE-2009-3606, CVE-2009-3608, CVE-2009-3609)

KOffice in Ubuntu 9.04 uses a very old version of Xpdf to import PDFs into
KWord. Upstream KDE no longer supports PDF import in KOffice and as a
result it was dropped in Ubuntu 9.10. While an attempt was made to fix the
above issues, the maintenance burden for supporting this very old version
of Xpdf outweighed its utility, and PDF import is now also disabled in
Ubuntu 9.04.");

  script_tag(name:"affected", value:"'koffice' package(s) on Ubuntu 9.04.");

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

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"kword", ver:"1:1.6.3-7ubuntu6.1", rls:"UBUNTU9.04"))) {
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
