# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55089");
  script_cve_id("CVE-2005-2450");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-776)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-776");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-776");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-776");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-776 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several bugs were discovered in Clam AntiVirus, the antivirus scanner for Unix, designed for integration with mail servers to perform attachment scanning. The following problems were identified:

CAN-2005-2450

Neel Mehta and Alex Wheeler discovered that Clam AntiVirus is vulnerable to integer overflows when handling the TNEF, CHM and FSG file formats.

CVE-NOMATCH Mark Pizzolato fixed a possible infinite loop that could cause a denial of service.

The old stable distribution (woody) is not affected as it doesn't contain clamav.

For the stable distribution (sarge) these problems have been fixed in version 0.84-2.sarge.2.

For the unstable distribution (sid) these problems have been fixed in version 0.86.2-1.

We recommend that you upgrade your clamav package.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav1", ver:"0.84-2.sarge.2", rls:"DEB3.1"))) {
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
