# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703485");
  script_cve_id("CVE-2013-7448");
  script_tag(name:"creation_date", value:"2016-02-19 23:00:00 +0000 (Fri, 19 Feb 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-10 19:05:00 +0000 (Thu, 10 Mar 2016)");

  script_name("Debian: Security Advisory (DSA-3485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3485");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3485");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3485");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'didiwiki' package(s) announced via the DSA-3485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Izmailov discovered that didiwiki, a wiki implementation, failed to correctly validate user-supplied input, thus allowing a malicious user to access any part of the filesystem.

For the oldstable distribution (wheezy), this problem has been fixed in version 0.5-11+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 0.5-11+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this problem has been fixed in version 0.5-12.

We recommend that you upgrade your didiwiki packages.");

  script_tag(name:"affected", value:"'didiwiki' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"didiwiki", ver:"0.5-11+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"didiwiki", ver:"0.5-11+deb8u1", rls:"DEB8"))) {
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
