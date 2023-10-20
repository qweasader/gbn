# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702852");
  script_cve_id("CVE-2013-6487");
  script_tag(name:"creation_date", value:"2014-02-05 23:00:00 +0000 (Wed, 05 Feb 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2852)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2852");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2852");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2852");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgadu' package(s) announced via the DSA-2852 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yves Younan and Ryan Pentney discovered that libgadu, a library for accessing the Gadu-Gadu instant messaging service, contained an integer overflow leading to a buffer overflow. Attackers which impersonate the server could crash clients and potentially execute arbitrary code.

For the oldstable distribution (squeeze), this problem has been fixed in version 1:1.9.0-2+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 1:1.11.2-1+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 1:1.11.3-1.

We recommend that you upgrade your libgadu packages.");

  script_tag(name:"affected", value:"'libgadu' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-dev", ver:"1:1.9.0-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-doc", ver:"1:1.9.0-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3", ver:"1:1.9.0-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3-dbg", ver:"1:1.9.0-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-dev", ver:"1:1.11.2-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-doc", ver:"1:1.11.2-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3", ver:"1:1.11.2-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3-dbg", ver:"1:1.11.2-1+deb7u1", rls:"DEB7"))) {
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
