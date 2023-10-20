# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56859");
  script_cve_id("CVE-2005-4744", "CVE-2006-1354");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1089");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1089");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1089");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freeradius' package(s) announced via the DSA-1089 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in freeradius, a high-performance and highly configurable RADIUS server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-4744

SuSE researchers have discovered several off-by-one errors may allow remote attackers to cause a denial of service and possibly execute arbitrary code.

CVE-2006-1354

Due to insufficient input validation it is possible for a remote attacker to bypass authentication or cause a denial of service.

The old stable distribution (woody) does not contain this package.

For the stable distribution (sarge) this problem has been fixed in version 1.0.2-4sarge1.

For the unstable distribution (sid) this problem has been fixed in version 1.1.0-1.2.

We recommend that you upgrade your freeradius package.");

  script_tag(name:"affected", value:"'freeradius' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"1.0.2-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-dialupadmin", ver:"1.0.2-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-iodbc", ver:"1.0.2-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-krb5", ver:"1.0.2-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-ldap", ver:"1.0.2-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-mysql", ver:"1.0.2-4sarge1", rls:"DEB3.1"))) {
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
