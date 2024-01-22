# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71140");
  script_cve_id("CVE-2011-1777", "CVE-2011-1778");
  script_tag(name:"creation_date", value:"2012-03-12 15:31:25 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2413-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2413-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2413-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2413");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libarchive' package(s) announced via the DSA-2413-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two buffer overflows have been discovered in libarchive, a library providing a flexible interface for reading and writing archives in various formats. The possible buffer overflows while reading ISO 9660 or tar streams allow remote attackers to execute arbitrary code depending on the application that makes use of this functionality.

For the stable distribution (squeeze), this problem has been fixed in version 2.8.4-1+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem has been fixed in version 2.8.5-5.

We recommend that you upgrade your libarchive packages.");

  script_tag(name:"affected", value:"'libarchive' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bsdcpio", ver:"2.8.4-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"2.8.4-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"2.8.4-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive1", ver:"2.8.4-1+squeeze1", rls:"DEB6"))) {
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
