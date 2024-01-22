# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704284");
  script_cve_id("CVE-2018-16435");
  script_tag(name:"creation_date", value:"2018-09-03 22:00:00 +0000 (Mon, 03 Sep 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Debian: Security Advisory (DSA-4284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4284-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4284-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4284");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lcms2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lcms2' package(s) announced via the DSA-4284-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Quang Nguyen discovered an integer overflow in the Little CMS 2 colour management library, which could result in denial of service and potentially the execution of arbitrary code if a malformed IT8 calibration file is processed.

For the stable distribution (stretch), this problem has been fixed in version 2.8-4+deb9u1.

We recommend that you upgrade your lcms2 packages.

For the detailed security status of lcms2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'lcms2' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-2", ver:"2.8-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-dev", ver:"2.8-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-utils", ver:"2.8-4+deb9u1", rls:"DEB9"))) {
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
