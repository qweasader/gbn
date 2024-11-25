# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.3814");
  script_cve_id("CVE-2024-34397");
  script_tag(name:"creation_date", value:"2024-05-14 04:18:41 +0000 (Tue, 14 May 2024)");
  script_version("2024-05-14T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-05-14 05:05:26 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3814-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3814-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-3814-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glib2.0' package(s) announced via the DLA-3814-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-dev-bin", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-tests", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-udeb", ver:"2.58.3-2+deb10u6", rls:"DEB10"))) {
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
