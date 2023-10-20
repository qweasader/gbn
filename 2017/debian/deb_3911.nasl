# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703911");
  script_cve_id("CVE-2017-1000083");
  script_tag(name:"creation_date", value:"2017-07-13 22:00:00 +0000 (Thu, 13 Jul 2017)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3911)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3911");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3911");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3911");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evince' package(s) announced via the DSA-3911 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm discovered that the Evince document viewer made insecure use of tar when opening tar comic book archives (CBT). Opening a malicious CBT archive could result in the execution of arbitrary code. This update disables the CBT format entirely.

For the oldstable distribution (jessie), this problem has been fixed in version 3.14.1-2+deb8u2.

For the stable distribution (stretch), this problem has been fixed in version 3.22.1-3+deb9u1.

For the unstable distribution (sid), this problem has been fixed in version 3.22.1-4.

We recommend that you upgrade your evince packages.");

  script_tag(name:"affected", value:"'evince' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"evince", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-common", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-dbg", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-gtk", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-evince-3.0", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevdocument3-4", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevince-dev", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevview3-3", ver:"3.14.1-2+deb8u2", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"browser-plugin-evince", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-common", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-gtk", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-evince-3.0", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevdocument3-4", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevince-dev", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevview3-3", ver:"3.22.1-3+deb9u1", rls:"DEB9"))) {
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
