# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72568");
  script_cve_id("CVE-2012-4523", "CVE-2012-4566");
  script_tag(name:"creation_date", value:"2012-11-16 08:15:41 +0000 (Fri, 16 Nov 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2573)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2573");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2573");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2573");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'radsecproxy' package(s) announced via the DSA-2573 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ralf Paffrath reported that Radsecproxy, a RADIUS protocol proxy, mixed up pre- and post-handshake verification of clients. This vulnerability may wrongly accept clients without checking their certificate chain under certain configurations.

Raphael Geissert spotted that the fix for CVE-2012-4523 was incomplete, giving origin to CVE-2012-4566. Both vulnerabilities are fixed with this update.

Notice that this fix may make Radsecproxy reject some clients that are currently (erroneously) being accepted.

For the stable distribution (squeeze), these problems have been fixed in version 1.4-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in version 1.6.2-1.

For the unstable distribution (sid), these problems have been fixed in version 1.6.2-1.

We recommend that you upgrade your radsecproxy packages.");

  script_tag(name:"affected", value:"'radsecproxy' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"radsecproxy", ver:"1.4-1+squeeze1", rls:"DEB6"))) {
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
