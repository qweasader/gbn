# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892877");
  script_cve_id("CVE-2019-17545", "CVE-2021-45943");
  script_tag(name:"creation_date", value:"2022-01-13 02:00:06 +0000 (Thu, 13 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-21 17:02:24 +0000 (Mon, 21 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-2877-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2877-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2877-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gdal");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gdal' package(s) announced via the DLA-2877-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues were found in GDAL, a geospatial library, that could lead to denial of service via application crash or possibly the execution of arbitrary code if maliciously crafted data was parsed.

For Debian 9 stretch, these problems have been fixed in version 2.1.2+dfsg-5+deb9u1.

We recommend that you upgrade your gdal packages.

For the detailed security status of gdal please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gdal' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gdal-bin", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdal-dev", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdal-doc", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdal-java", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdal-perl", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdal20", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-gdal", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-gdal", ver:"2.1.2+dfsg-5+deb9u1", rls:"DEB9"))) {
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
