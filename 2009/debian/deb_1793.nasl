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
  script_oid("1.3.6.1.4.1.25623.1.0.63958");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_tag(name:"creation_date", value:"2009-05-11 18:24:31 +0000 (Mon, 11 May 2009)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1793)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1793");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1793");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1793");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdegraphics' package(s) announced via the DSA-1793 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kpdf, a Portable Document Format (PDF) viewer for KDE, is based on the xpdf program and thus suffers from similar flaws to those described in DSA-1790.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0146

Multiple buffer overflows in the JBIG2 decoder in kpdf allow remote attackers to cause a denial of service (crash) via a crafted PDF file, related to (1) JBIG2SymbolDict::setBitmap and (2) JBIG2Stream::readSymbolDictSeg.

CVE-2009-0147

Multiple integer overflows in the JBIG2 decoder in kpdf allow remote attackers to cause a denial of service (crash) via a crafted PDF file, related to (1) JBIG2Stream::readSymbolDictSeg, (2) JBIG2Stream::readSymbolDictSeg, and (3) JBIG2Stream::readGenericBitmap.

CVE-2009-0165

Integer overflow in the JBIG2 decoder in kpdf has unspecified impact related to 'g*allocn.'

CVE-2009-0166

The JBIG2 decoder in kpdf allows remote attackers to cause a denial of service (crash) via a crafted PDF file that triggers a free of uninitialized memory.

CVE-2009-0799

The JBIG2 decoder in kpdf allows remote attackers to cause a denial of service (crash) via a crafted PDF file that triggers an out-of-bounds read.

CVE-2009-0800

Multiple 'input validation flaws' in the JBIG2 decoder in kpdf allow remote attackers to execute arbitrary code via a crafted PDF file.

CVE-2009-1179

Integer overflow in the JBIG2 decoder in kpdf allows remote attackers to execute arbitrary code via a crafted PDF file.

CVE-2009-1180

The JBIG2 decoder in kpdf allows remote attackers to execute arbitrary code via a crafted PDF file that triggers a free of invalid data.

CVE-2009-1181

The JBIG2 decoder in kpdf allows remote attackers to cause a denial of service (crash) via a crafted PDF file that triggers a NULL pointer dereference.

CVE-2009-1182

Multiple buffer overflows in the JBIG2 MMR decoder in kpdf allow remote attackers to execute arbitrary code via a crafted PDF file.

CVE-2009-1183

The JBIG2 MMR decoder in kpdf allows remote attackers to cause a denial of service (infinite loop and hang) via a crafted PDF file.

The old stable distribution (etch), these problems have been fixed in version 3.5.5-3etch3.

For the stable distribution (lenny), these problems have been fixed in version 3.5.9-3+lenny1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your kdegraphics packages.");

  script_tag(name:"affected", value:"'kdegraphics' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"kamera", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kcoloredit", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-dbg", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-dev", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-doc-html", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-kfile-plugins", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdvi", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfax", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfaxview", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kgamma", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kghostview", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kiconedit", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmrml", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolourpaint", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kooka", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpdf", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpovmodeler", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kruler", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksnapshot", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksvg", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kuickshow", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kview", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kviewshell", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkscan-dev", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkscan1", ver:"4:3.5.5-3etch3", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"kamera", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kcoloredit", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-dbg", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-dev", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-doc-html", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-kfile-plugins", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdvi", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfax", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfaxview", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kgamma", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kghostview", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kiconedit", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmrml", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolourpaint", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kooka", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpdf", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpovmodeler", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kruler", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksnapshot", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksvg", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kuickshow", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kview", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kviewshell", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkscan-dev", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkscan1", ver:"4:3.5.9-3+lenny1", rls:"DEB5"))) {
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
