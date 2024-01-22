# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703990");
  script_cve_id("CVE-2017-14603");
  script_tag(name:"creation_date", value:"2017-10-02 22:00:00 +0000 (Mon, 02 Oct 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-05 23:03:00 +0000 (Sun, 05 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3990-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3990-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3990-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3990");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-3990-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Klaus-Peter Junghann discovered that insufficient validation of RTCP packets in Asterisk may result in an information leak. Please see the upstream advisory at [link moved to references] for additional details.

For the oldstable distribution (jessie), this problem has been fixed in version 1:11.13.1~dfsg-2+deb8u4.

For the stable distribution (stretch), this problem has been fixed in version 1:13.14.1~dfsg-2+deb9u2.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-vpb", ver:"1:11.13.1~dfsg-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-vpb", ver:"1:13.14.1~dfsg-2+deb9u2", rls:"DEB9"))) {
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
