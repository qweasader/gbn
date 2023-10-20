# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702659");
  script_cve_id("CVE-2013-1915");
  script_tag(name:"creation_date", value:"2013-04-08 22:00:00 +0000 (Mon, 08 Apr 2013)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2659)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2659");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2659");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2659");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapache-mod-security' package(s) announced via the DSA-2659 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timur Yunusov and Alexey Osipov from Positive Technologies discovered that the XML files parser of ModSecurity, an Apache module whose purpose is to tighten the Web application security, is vulnerable to XML external entities attacks. A specially-crafted XML file provided by a remote attacker, could lead to local file disclosure or excessive resources (CPU, memory) consumption when processed.

This update introduces a SecXmlExternalEntity option which is Off by default. This will disable the ability of libxml2 to load external entities.

For the stable distribution (squeeze), this problem has been fixed in version 2.5.12-1+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in version 2.6.6-6 of the modsecurity-apache package.

For the unstable distribution (sid), this problem has been fixed in version 2.6.6-6 of the modsecurity-apache package.

We recommend that you upgrade your libapache-mod-security packages.");

  script_tag(name:"affected", value:"'libapache-mod-security' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-security", ver:"2.5.12-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mod-security-common", ver:"2.5.12-1+squeeze2", rls:"DEB6"))) {
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
