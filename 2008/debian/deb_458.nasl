# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53710");
  script_cve_id("CVE-2004-0150");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-458");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-458");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-458");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python2.2' package(s) announced via the DSA-458 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security advisory corrects DSA 458-2 which caused a problem in the gethostbyaddr routine.

The original advisory said:

Sebastian Schmidt discovered a buffer overflow bug in Python's getaddrinfo function, which could allow an IPv6 address, supplied by a remote attacker via DNS, to overwrite memory on the stack.

This bug only exists in python 2.2 and 2.2.1, and only when IPv6 support is disabled. The python2.2 package in Debian woody meets these conditions (the 'python' package does not).

For the stable distribution (woody), this bug has been fixed in version 2.2.1-4.6.

The testing and unstable distribution (sarge and sid) are not affected by this problem.

We recommend that you update your python2.2 packages.");

  script_tag(name:"affected", value:"'python2.2' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.2", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-dev", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-doc", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-elisp", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-examples", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-gdbm", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-mpz", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-tk", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.2-xmlbase", ver:"2.2.1-4.6", rls:"DEB3.0"))) {
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
