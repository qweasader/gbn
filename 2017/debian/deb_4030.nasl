# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704030");
  script_cve_id("CVE-2017-16651");
  script_tag(name:"creation_date", value:"2017-11-08 23:00:00 +0000 (Wed, 08 Nov 2017)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 21:08:00 +0000 (Thu, 04 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4030)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4030");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4030");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4030");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'roundcube' package(s) announced via the DSA-4030 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A file disclosure vulnerability was discovered in roundcube, a skinnable AJAX based webmail solution for IMAP servers. An authenticated attacker can take advantage of this flaw to read roundcube's configuration files.

For the stable distribution (stretch), this problem has been fixed in version 1.2.3+dfsg.1-4+deb9u1.

For the unstable distribution (sid), this problem has been fixed in version 1.3.3+dfsg.1-1.

We recommend that you upgrade your roundcube packages.");

  script_tag(name:"affected", value:"'roundcube' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.2.3+dfsg.1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.2.3+dfsg.1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-mysql", ver:"1.2.3+dfsg.1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-pgsql", ver:"1.2.3+dfsg.1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.2.3+dfsg.1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-sqlite3", ver:"1.2.3+dfsg.1-4+deb9u1", rls:"DEB9"))) {
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
