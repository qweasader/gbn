# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703957");
  script_cve_id("CVE-2017-11399", "CVE-2017-11665", "CVE-2017-11719", "CVE-2017-9608", "CVE-2017-9993");
  script_tag(name:"creation_date", value:"2017-08-27 22:00:00 +0000 (Sun, 27 Aug 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 22:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-3957-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-3957-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3957-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3957");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg' package(s) announced via the DSA-3957-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in FFmpeg, a multimedia player, server and encoder. These issues could lead to Denial-of-Service and, in some situation, the execution of arbitrary code.

CVE-2017-9608

Yihan Lian of Qihoo 360 GearTeam discovered a NULL pointer access when parsing a crafted MOV file.

CVE-2017-9993

Thierry Foucu discovered that it was possible to leak information from files and symlinks ending in common multimedia extensions, using the HTTP Live Streaming.

CVE-2017-11399

Liu Bingchang of IIE discovered an integer overflow in the APE decoder that can be triggered by a crafted APE file.

CVE-2017-11665

JunDong Xie of Ant-financial Light-Year Security Lab discovered that an attacker able to craft a RTMP stream can crash FFmpeg.

CVE-2017-11719

Liu Bingchang of IIE discovered an out-of-bound access that can be triggered by a crafted DNxHD file.

For the stable distribution (stretch), these problems have been fixed in version 7:3.2.7-1~deb9u1.

We recommend that you upgrade your ffmpeg packages.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra57", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec57", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice57", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra6", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter6", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat57", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample3", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil55", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc54", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample2", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale4", ver:"7:3.2.7-1~deb9u1", rls:"DEB9"))) {
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
