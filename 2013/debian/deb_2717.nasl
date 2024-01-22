# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702717");
  script_cve_id("CVE-2013-2210");
  script_tag(name:"creation_date", value:"2013-06-27 22:00:00 +0000 (Thu, 27 Jun 2013)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2717-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2717-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2717");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xml-security-c' package(s) announced via the DSA-2717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jon Erickson of iSIGHT Partners Labs discovered a heap overflow in xml-security-c, an implementation of the XML Digital Security specification. The fix to address CVE-2013-2154 introduced the possibility of a heap overflow in the processing of malformed XPointer expressions in the XML Signature Reference processing code, possibly leading to arbitrary code execution.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.5.1-3+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in version 1.6.1-5+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 1.6.1-7.

We recommend that you upgrade your xml-security-c packages.");

  script_tag(name:"affected", value:"'xml-security-c' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxml-security-c-dev", ver:"1.5.1-3+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml-security-c15", ver:"1.5.1-3+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml-security-c-dev", ver:"1.6.1-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml-security-c16", ver:"1.6.1-5+deb7u2", rls:"DEB7"))) {
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
