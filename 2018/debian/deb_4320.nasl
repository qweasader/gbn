# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704320");
  script_cve_id("CVE-2018-12227", "CVE-2018-17281", "CVE-2018-7284", "CVE-2018-7286");
  script_tag(name:"creation_date", value:"2018-10-15 22:00:00 +0000 (Mon, 15 Oct 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 18:54:00 +0000 (Fri, 01 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-4320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4320-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4320-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4320");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/asterisk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-4320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Asterisk, an open source PBX and telephony toolkit, which may result in denial of service or information disclosure.

For the stable distribution (stretch), these problems have been fixed in version 1:13.14.1~dfsg-2+deb9u4.

We recommend that you upgrade your asterisk packages.

For the detailed security status of asterisk please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-vpb", ver:"1:13.14.1~dfsg-2+deb9u4", rls:"DEB9"))) {
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
