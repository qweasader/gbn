# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64112");
  script_cve_id("CVE-2008-5519");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1810)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1810");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1810");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1810");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapache-mod-jk' package(s) announced via the DSA-1810 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure flaw was found in mod_jk, the Tomcat Connector module for Apache. If a buggy client included the 'Content-Length' header without providing request body data, or if a client sent repeated requests very quickly, one client could obtain a response intended for another client.

The oldstable distribution (etch), this problem has been fixed in version 1:1.2.18-3etch2.

For the stable distribution (lenny), this problem has been fixed in version 1:1.2.26-2+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 1:1.2.26-2.1.

We recommend that you upgrade your libapache-mod-jk packages.");

  script_tag(name:"affected", value:"'libapache-mod-jk' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-jk", ver:"1:1.2.18-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-jk-doc", ver:"1:1.2.18-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-jk", ver:"1:1.2.18-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-jk-doc", ver:"1:1.2.26-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-jk", ver:"1:1.2.26-2+lenny1", rls:"DEB5"))) {
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
