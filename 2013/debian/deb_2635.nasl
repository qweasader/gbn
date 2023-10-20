# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702635");
  script_cve_id("CVE-2013-1049");
  script_tag(name:"creation_date", value:"2013-02-28 23:00:00 +0000 (Thu, 28 Feb 2013)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2635)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2635");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2635");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2635");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cfingerd' package(s) announced via the DSA-2635 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Malcolm Scott discovered a remote-exploitable buffer overflow in the RFC1413 (ident) client of cfingerd, a configurable finger daemon. This vulnerability was introduced in a previously applied patch to the cfingerd package in 1.4.3-3.

For the stable distribution (squeeze), this problem has been fixed in version 1.4.3-3+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 1.4.3-3.1.

For the unstable distribution (sid), this problem has been fixed in version 1.4.3-3.1.

We recommend that you upgrade your cfingerd packages.");

  script_tag(name:"affected", value:"'cfingerd' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cfingerd", ver:"1.4.3-3+squeeze1", rls:"DEB6"))) {
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
