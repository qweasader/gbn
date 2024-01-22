# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703753");
  script_cve_id("CVE-2016-9941", "CVE-2016-9942");
  script_tag(name:"creation_date", value:"2017-01-04 23:00:00 +0000 (Wed, 04 Jan 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-3753-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3753-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3753-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3753");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvncserver' package(s) announced via the DSA-3753-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvncserver, a collection of libraries used to implement VNC/RFB clients and servers, incorrectly processed incoming network packets. This resulted in several heap-based buffer overflows, allowing a rogue server to either cause a DoS by crashing the client, or potentially execute arbitrary code on the client side.

For the stable distribution (jessie), these problems have been fixed in version 0.9.9+dfsg2-6.1+deb8u2.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 0.9.11+dfsg-1.

We recommend that you upgrade your libvncserver packages.");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient0", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient0-dbg", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver-config", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver-dev", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver0", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver0-dbg", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linuxvnc", ver:"0.9.9+dfsg2-6.1+deb8u2", rls:"DEB8"))) {
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
