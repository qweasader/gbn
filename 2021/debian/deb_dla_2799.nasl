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
  script_oid("1.3.6.1.4.1.25623.1.0.892799");
  script_cve_id("CVE-2016-1516", "CVE-2017-1000450", "CVE-2017-12597", "CVE-2017-12598", "CVE-2017-12599", "CVE-2017-12601", "CVE-2017-12603", "CVE-2017-12604", "CVE-2017-12605", "CVE-2017-12606", "CVE-2017-12862", "CVE-2017-12863", "CVE-2017-12864", "CVE-2017-17760", "CVE-2018-5268", "CVE-2018-5269", "CVE-2019-14493", "CVE-2019-15939");
  script_tag(name:"creation_date", value:"2021-10-31 02:00:20 +0000 (Sun, 31 Oct 2021)");
  script_version("2023-03-09T10:20:44+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:44 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 22:05:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-2799)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2799");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2799");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/opencv");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opencv' package(s) announced via the DLA-2799 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in OpenCV, the Open Computer Vision Library. Buffer overflows, NULL pointer dereferences and out-of-bounds write errors may lead to a denial-of-service or other unspecified impact.

For Debian 9 stretch, these problems have been fixed in version 2.4.9.1+dfsg1-2+deb9u1.

We recommend that you upgrade your opencv packages.

For the detailed security status of opencv please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'opencv' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libcv-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcv2.4", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcvaux-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcvaux2.4", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhighgui-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhighgui2.4", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-calib3d-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-calib3d2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-contrib-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-contrib2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-features2d-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-features2d2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-flann-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-flann2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-gpu-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-gpu2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-highgui-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-highgui2.4-deb0", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgproc-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgproc2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-legacy-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-legacy2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ml-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ml2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-objdetect-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-objdetect2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ocl-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ocl2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-photo-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-photo2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-stitching-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-stitching2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-superres-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-superres2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ts-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ts2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-video-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-video2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-videostab-dev", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-videostab2.4v5", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv2.4-java", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv2.4-jni", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opencv-data", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opencv-doc", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-opencv", ver:"2.4.9.1+dfsg1-2+deb9u1", rls:"DEB9"))) {
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
