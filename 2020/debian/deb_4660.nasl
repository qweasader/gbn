# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704660");
  script_cve_id("CVE-2020-11728", "CVE-2020-11729");
  script_tag(name:"creation_date", value:"2020-04-22 03:00:07 +0000 (Wed, 22 Apr 2020)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4660-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4660-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4660-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4660");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/awl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'awl' package(s) announced via the DSA-4660-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Bartlett discovered that awl, DAViCal Andrew's Web Libraries, did not properly handle session management: this would allow a malicious user to impersonate other sessions or users.

For the oldstable distribution (stretch), these problems have been fixed in version 0.57-1+deb9u1.

For the stable distribution (buster), these problems have been fixed in version 0.60-1+deb10u1.

We recommend that you upgrade your awl packages.

For the detailed security status of awl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'awl' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"awl-doc", ver:"0.60-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libawl-php", ver:"0.60-1+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"awl-doc", ver:"0.57-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libawl-php", ver:"0.57-1+deb9u1", rls:"DEB9"))) {
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
