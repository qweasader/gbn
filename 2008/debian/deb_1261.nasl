# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58016");
  script_cve_id("CVE-2007-0555");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1261)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1261");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1261");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1261");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql' package(s) announced via the DSA-1261 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the PostgreSQL database performs insufficient type checking for SQL function arguments, which might lead to denial of service or information disclosure.

For the stable distribution (sarge) this problem has been fixed in version 7.4.7-6sarge4.

For the upcoming stable distribution (etch) this problem has been fixed in version 8.1.7-1 of the postgresql-8.1 package.

For the unstable distribution (sid) this problem has been fixed in version 8.1.7-1 of the postgresql-8.1 package.

We recommend that you upgrade your PostgreSQL packages.");

  script_tag(name:"affected", value:"'postgresql' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg4", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtcl", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtcl-dev", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq3", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-dev", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc", ver:"7.4.7-6sarge4", rls:"DEB3.1"))) {
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
