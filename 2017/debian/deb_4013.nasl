# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704013");
  script_cve_id("CVE-2016-1626", "CVE-2016-1628", "CVE-2016-5152", "CVE-2016-9118", "CVE-2017-14039", "CVE-2017-14040", "CVE-2017-14041", "CVE-2017-14152");
  script_tag(name:"creation_date", value:"2017-10-30 23:00:00 +0000 (Mon, 30 Oct 2017)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 19:51:00 +0000 (Tue, 02 Feb 2021)");

  script_name("Debian: Security Advisory (DSA-4013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4013");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4013");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4013");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg2' package(s) announced via the DSA-4013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in OpenJPEG, a JPEG 2000 image compression / decompression library, may result in denial of service or the execution of arbitrary code if a malformed JPEG 2000 file is processed.

For the oldstable distribution (jessie), these problems have been fixed in version 2.1.0-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed in version 2.1.2-1.1+deb9u2.

We recommend that you upgrade your openjpeg2 packages.");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dbg", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dbg", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dev", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dev", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-tools", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-tools", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d-tools", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d-tools", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-dec-server", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-dec-server", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-server", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-server", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-viewer", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.1.0-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.1.0-2+deb8u3+b1", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dbg", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dev", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-tools", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d-tools", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-dec-server", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-server", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-viewer", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.1.2-1.1+deb9u2", rls:"DEB9"))) {
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
