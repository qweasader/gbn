# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704588");
  script_cve_id("CVE-2019-14853", "CVE-2019-14859");
  script_tag(name:"creation_date", value:"2019-12-18 03:00:53 +0000 (Wed, 18 Dec 2019)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 18:32:00 +0000 (Tue, 08 Dec 2020)");

  script_name("Debian: Security Advisory (DSA-4588-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4588-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4588-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4588");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python-ecdsa");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-ecdsa' package(s) announced via the DSA-4588-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that python-ecdsa, a cryptographic signature library for Python, incorrectly handled certain signatures. A remote attacker could use this issue to cause python-ecdsa to either not warn about incorrect signatures, or generate exceptions resulting in a denial-of-service.

For the oldstable distribution (stretch), these problems have been fixed in version 0.13-2+deb9u1.

For the stable distribution (buster), these problems have been fixed in version 0.13-3+deb10u1.

We recommend that you upgrade your python-ecdsa packages.

For the detailed security status of python-ecdsa please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'python-ecdsa' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-ecdsa", ver:"0.13-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ecdsa", ver:"0.13-3+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-ecdsa", ver:"0.13-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ecdsa", ver:"0.13-2+deb9u1", rls:"DEB9"))) {
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
