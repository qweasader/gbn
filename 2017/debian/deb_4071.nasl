# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704071");
  script_cve_id("CVE-2017-17512");
  script_tag(name:"creation_date", value:"2017-12-20 23:00:00 +0000 (Wed, 20 Dec 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-4071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4071-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4071-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4071");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sensible-utils");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sensible-utils' package(s) announced via the DSA-4071-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gabriel Corona reported that sensible-browser from sensible-utils, a collection of small utilities used to sensibly select and spawn an appropriate browser, editor or pager, does not validate strings before launching the program specified by the BROWSER environment variable, potentially allowing a remote attacker to conduct argument-injection attacks if a user is tricked into processing a specially crafted URL.

For the oldstable distribution (jessie), this problem has been fixed in version 0.0.9+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 0.0.9+deb9u1.

We recommend that you upgrade your sensible-utils packages.

For the detailed security status of sensible-utils please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'sensible-utils' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sensible-utils", ver:"0.0.9+deb8u1", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sensible-utils", ver:"0.0.9+deb9u1", rls:"DEB9"))) {
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
