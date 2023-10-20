# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704299");
  script_cve_id("CVE-2018-17407");
  script_tag(name:"creation_date", value:"2018-09-20 22:00:00 +0000 (Thu, 20 Sep 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-15 16:11:00 +0000 (Thu, 15 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4299)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4299");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4299");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4299");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/texlive-bin");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'texlive-bin' package(s) announced via the DSA-4299 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nick Roessler from the University of Pennsylvania has found a buffer overflow in texlive-bin, the executables for TexLive, the popular distribution of TeX document production system.

This buffer overflow can be used for arbitrary code execution by crafting a special type1 font (.pfb) and provide it to users running pdf(la)tex, dvips or luatex in a way that the font is loaded.

For the stable distribution (stretch), this problem has been fixed in version 2016.20160513.41080.dfsg-2+deb9u1.

We recommend that you upgrade your texlive-bin packages.

For the detailed security status of texlive-bin please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'texlive-bin' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkpathsea6", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libptexenc-dev", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libptexenc1", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsynctex-dev", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsynctex1", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtexlua52", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtexlua52-dev", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtexluajit-dev", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtexluajit2", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2016.20160513.41080.dfsg-2+deb9u1", rls:"DEB9"))) {
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
