# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702793");
  script_cve_id("CVE-2013-0844", "CVE-2013-0850", "CVE-2013-0853", "CVE-2013-0854", "CVE-2013-0857", "CVE-2013-0858", "CVE-2013-0866");
  script_tag(name:"creation_date", value:"2013-11-08 23:00:00 +0000 (Fri, 08 Nov 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2793)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2793");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2793");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2793");
  script_xref(name:"URL", value:"http://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v0.8.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DSA-2793 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and decoders of the libav multimedia library. The CVE IDs mentioned above are just a small portion of the security issues fixed in this update. A full list of the changes is available at [link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 0.8.9-1.

For the unstable distribution (sid), these problems have been fixed in version 9.10-1.

We recommend that you upgrade your libav packages.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-dbg", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-doc", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-extra-dbg", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra-53", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec53", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-extra-53", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice53", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra-2", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter2", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-extra-53", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat53", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-extra-51", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil51", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-extra-52", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc52", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-extra-2", ver:"6:0.8.9-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale2", ver:"6:0.8.9-1", rls:"DEB7"))) {
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
