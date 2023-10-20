# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63147");
  script_cve_id("CVE-2009-0050");
  script_tag(name:"creation_date", value:"2009-01-13 21:38:32 +0000 (Tue, 13 Jan 2009)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1700)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1700");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1700");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1700");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lasso' package(s) announced via the DSA-1700 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Lasso, a library for Liberty Alliance and SAML protocols performs incorrect validation of the return value of OpenSSL's DSA_verify() function.

For the stable distribution (etch), this problem has been fixed in version 0.6.5-3+etch1.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), this problem has been fixed in version 2.2.1-2.

We recommend that you upgrade your lasso package.");

  script_tag(name:"affected", value:"'lasso' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblasso-java", ver:"0.6.5-3+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblasso3", ver:"0.6.5-3+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblasso3-dev", ver:"0.6.5-3+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-lasso", ver:"0.6.5-3+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-lasso", ver:"0.6.5-3+etch1", rls:"DEB4"))) {
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
