# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704006");
  script_cve_id("CVE-2017-14685", "CVE-2017-14686", "CVE-2017-14687", "CVE-2017-15587");
  script_tag(name:"creation_date", value:"2017-10-23 22:00:00 +0000 (Mon, 23 Oct 2017)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-27 11:29:00 +0000 (Tue, 27 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4006)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4006");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4006");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4006");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mupdf' package(s) announced via the DSA-4006 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in MuPDF, a PDF file viewer, which may result in denial of service or the execution of arbitrary code.

CVE-2017-14685, CVE-2017-14686, and CVE-2017-14687 WangLin discovered that a crafted .xps file can crash MuPDF and potentially execute arbitrary code in several ways, since the application makes unchecked assumptions on the entry format.

CVE-2017-15587

Terry Chia and Jeremy Heng discovered an integer overflow that can cause arbitrary code execution via a crafted .pdf file.

For the stable distribution (stretch), these problems have been fixed in version 1.9a+ds1-4+deb9u1.

We recommend that you upgrade your mupdf packages.");

  script_tag(name:"affected", value:"'mupdf' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.5-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.5-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.5-1+deb8u3", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.9a+ds1-4+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.9a+ds1-4+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.9a+ds1-4+deb9u2", rls:"DEB9"))) {
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
