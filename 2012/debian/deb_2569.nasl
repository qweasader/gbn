# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.72564");
  script_cve_id("CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4182", "CVE-2012-4186", "CVE-2012-4188");
  script_tag(name:"creation_date", value:"2012-11-16 08:09:50 +0000 (Fri, 16 Nov 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2569)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2569");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2569");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2569");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2569 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Icedove, Debian's version of the Mozilla Thunderbird mail client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-3982

Multiple unspecified vulnerabilities in the browser engine allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors.

CVE-2012-3986

Icedove does not properly restrict calls to DOMWindowUtils methods, which allows remote attackers to bypass intended access restrictions via crafted JavaScript code.

CVE-2012-3990

A Use-after-free vulnerability in the IME State Manager implementation allows remote attackers to execute arbitrary code via unspecified vectors, related to the nsIContent::GetNameSpaceID function.

CVE-2012-3991

Icedove does not properly restrict JSAPI access to the GetProperty function, which allows remote attackers to bypass the Same Origin Policy and possibly have unspecified other impact via a crafted web site.

CVE-2012-4179

A use-after-free vulnerability in the nsHTMLCSSUtils::CreateCSSPropertyTxn function allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via unspecified vectors.

CVE-2012-4180

A heap-based buffer overflow in the nsHTMLEditor::IsPrevCharInNodeWhitespace function allows remote attackers to execute arbitrary code via unspecified vectors.

CVE-2012-4182

A use-after-free vulnerability in the nsTextEditRules::WillInsert function allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via unspecified vectors.

CVE-2012-4186

A heap-based buffer overflow in the nsWav-eReader::DecodeAudioData function allows remote attackers to execute arbitrary code via unspecified vectors.

CVE-2012-4188

A heap-based buffer overflow in the Convolve3x3 function allows remote attackers to execute arbitrary code via unspecified vectors.

For the stable distribution (squeeze), these problems have been fixed in version 3.0.11-1+squeeze14.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 10.0.9-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze14", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze14", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze14", rls:"DEB6"))) {
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
