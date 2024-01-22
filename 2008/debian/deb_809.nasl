# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55816");
  script_cve_id("CVE-2005-2794", "CVE-2005-2796");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-809-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-809-3");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-809-3");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-809");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid' package(s) announced via the DSA-809-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Certain aborted requests that trigger an assertion in squid, the popular WWW proxy cache, may allow remote attackers to cause a denial of service. This update also fixes a regression caused by DSA 751. For completeness below is the original advisory text:

Several vulnerabilities have been discovered in Squid, the popular WWW proxy cache. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2794

Certain aborted requests that trigger an assert may allow remote attackers to cause a denial of service.

CAN-2005-2796

Specially crafted requests can cause a denial of service.

For the oldstable distribution (woody) this problem has been fixed in version 2.4.6-2woody10.

For the stable distribution (sarge) these problems have been fixed in version 2.5.9-10sarge1.

For the unstable distribution (sid) these problems have been fixed in version 2.5.10-5.

We recommend that you upgrade your squid package.");

  script_tag(name:"affected", value:"'squid' package(s) on Debian 3.0, Debian 3.1.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"2.4.6-2woody11", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"2.4.6-2woody11", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"2.4.6-2woody11", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"2.5.9-10sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"2.5.9-10sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"2.5.9-10sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"2.5.9-10sarge1", rls:"DEB3.1"))) {
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
