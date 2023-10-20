# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66101");
  script_cve_id("CVE-2009-1382", "CVE-2009-2459");
  script_tag(name:"creation_date", value:"2009-10-27 00:37:56 +0000 (Tue, 27 Oct 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1917)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1917");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1917");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1917");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mimetex' package(s) announced via the DSA-1917 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mimetex, a lightweight alternative to MathML. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1382

Chris Evans and Damien Miller, discovered multiple stack-based buffer overflow. An attacker could execute arbitrary code via a TeX file with long picture, circle, input tags.

CVE-2009-2459

Chris Evans discovered that mimeTeX contained certain directives that may be unsuitable for handling untrusted user input. A remote attacker can obtain sensitive information.

For the oldstable distribution (etch), these problems have been fixed in version 1.50-1+etch1.

Due to a bug in the archive system, the fix for the stable distribution (lenny) will be released as version 1.50-1+lenny1 once it is available.

For the testing distribution (squeeze), and the unstable distribution (sid), these problems have been fixed in version 1.50-1.1.

We recommend that you upgrade your mimetex packages.");

  script_tag(name:"affected", value:"'mimetex' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mimetex", ver:"1.50-1+etch1", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mimetex", ver:"1.50-1+lenny1", rls:"DEB5"))) {
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
