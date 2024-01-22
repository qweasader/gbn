# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54477");
  script_cve_id("CVE-2005-2301", "CVE-2005-2302");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-771-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-771-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-771-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-771");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns' package(s) announced via the DSA-771-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in pdns, a versatile nameserver that can lead to a denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2301

Norbert Sendetzky and Jan de Groot discovered that the LDAP backend did not properly escape all queries, allowing it to fail and not answer queries anymore.

CAN-2005-2302

Wilco Baan discovered that queries from clients without recursion permission can temporarily blank out domains to clients with recursion permitted. This enables outside users to blank out a domain temporarily to normal users.

The old stable distribution (woody) does not contain pdns packages.

For the stable distribution (sarge) these problems have been fixed in version 2.9.17-13sarge1.

For the unstable distribution (sid) these problems have been fixed in version 2.9.18-1.

We recommend that you upgrade your pdns package.");

  script_tag(name:"affected", value:"'pdns' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"pdns", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-geo", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-sqlite", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-doc", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-recursor", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"2.9.17-13sarge1", rls:"DEB3.1"))) {
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
