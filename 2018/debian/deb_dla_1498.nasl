# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891498");
  script_cve_id("CVE-2018-14618");
  script_tag(name:"creation_date", value:"2018-09-09 22:00:00 +0000 (Sun, 09 Sep 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)");

  script_name("Debian: Security Advisory (DLA-1498-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1498-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1498-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DLA-1498-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a an integer overflow vulnerability in curl, a command line tool for transferring data over HTTP, etc.

For more information, please see:


For Debian 8 Jessie, this issue has been fixed in curl version 7.38.0-4+deb8u12.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.38.0-4+deb8u12", rls:"DEB8"))) {
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
