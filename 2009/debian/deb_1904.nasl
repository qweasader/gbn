# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65747");
  script_cve_id("CVE-2009-3490");
  script_tag(name:"creation_date", value:"2009-10-13 16:25:40 +0000 (Tue, 13 Oct 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1904)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1904");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1904");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1904");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wget' package(s) announced via the DSA-1904 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Stenberg discovered that wget, a network utility to retrieve files from the Web using HTTP(S) and FTP, is vulnerable to the 'Null Prefix Attacks Against SSL/TLS Certificates' published at the Blackhat conference some time ago. This allows an attacker to perform undetected man-in-the-middle attacks via a crafted ITU-T X.509 certificate with an injected null byte in the Common Name field.

For the oldstable distribution (etch), this problem has been fixed in version 1.10.2-2+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.11.4-2+lenny1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.12-1.

We recommend that you upgrade your wget packages.");

  script_tag(name:"affected", value:"'wget' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wget", ver:"1.10.2-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"wget", ver:"1.11.4-2+lenny1", rls:"DEB5"))) {
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
