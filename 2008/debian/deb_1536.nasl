# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.60658");
  script_cve_id("CVE-2007-1246", "CVE-2007-1387", "CVE-2008-0073", "CVE-2008-0486", "CVE-2008-1161");
  script_tag(name:"creation_date", value:"2008-04-07 18:38:54 +0000 (Mon, 07 Apr 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1536)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1536");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1536");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1536");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xine-lib' package(s) announced via the DSA-1536 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in Xine, a media player library, allowed for a denial of service or arbitrary code execution, which could be exploited through viewing malicious content. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1246 / CVE-2007-1387 The DMO_VideoDecoder_Open function does not set the biSize before use in a memcpy, which allows user-assisted remote attackers to cause a buffer overflow and possibly execute arbitrary code (applies to sarge only).

CVE-2008-0073

Array index error in the sdpplin_parse function allows remote RTSP servers to execute arbitrary code via a large streamid SDP parameter.

CVE-2008-0486

Array index vulnerability in libmpdemux/demux_audio.c might allow remote attackers to execute arbitrary code via a crafted FLAC tag, which triggers a buffer overflow (applies to etch only).

CVE-2008-1161

Buffer overflow in the Matroska demuxer allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a Matroska file with invalid frame sizes.

For the old stable distribution (sarge), these problems have been fixed in version 1.0.1-1sarge7.

For the stable distribution (etch), these problems have been fixed in version 1.1.2+dfsg-6.

For the unstable distribution (sid), these problems have been fixed in version 1.1.11-1.

We recommend that you upgrade your xine-lib package.");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine-dev", ver:"1.0.1-1sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.0.1-1sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.2+dfsg-6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.2+dfsg-6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.2+dfsg-6", rls:"DEB4"))) {
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
