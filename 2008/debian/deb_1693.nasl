# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63065");
  script_cve_id("CVE-2007-2865", "CVE-2007-5728", "CVE-2008-5587");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1693)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1693");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1693");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1693");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phppgadmin' package(s) announced via the DSA-1693 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpPgAdmin, a tool to administrate PostgreSQL database over the web. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2865

Cross-site scripting vulnerability allows remote attackers to inject arbitrary web script or HTML via the server parameter.

CVE-2007-5728

Cross-site scripting vulnerability allows remote attackers to inject arbitrary web script or HTML via PHP_SELF.

CVE-2008-5587

Directory traversal vulnerability allows remote attackers to read arbitrary files via _language parameter.

For the stable distribution (etch), these problems have been fixed in version 4.0.1-3.1etch2.

For the unstable distribution (sid), these problems have been fixed in version 4.2.1-1.1.

We recommend that you upgrade your phppgadmin package.");

  script_tag(name:"affected", value:"'phppgadmin' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"phppgadmin", ver:"4.0.1-3.1etch1", rls:"DEB4"))) {
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
