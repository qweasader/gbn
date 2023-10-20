# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63301");
  script_cve_id("CVE-2009-0260", "CVE-2009-0312");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1715)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1715");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1715");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1715");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moin' package(s) announced via the DSA-1715 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the AttachFile action in moin, a python clone of WikiWiki, is prone to cross-site scripting attacks (CVE-2009-0260). Another cross-site scripting vulnerability was discovered in the antispam feature (CVE-2009-0312).

For the stable distribution (etch) these problems have been fixed in version 1.5.3-1.2etch2.

For the testing (lenny) distribution these problems have been fixed in version 1.7.1-3+lenny1.

For the unstable (sid) distribution these problems have been fixed in version 1.8.1-1.1.

We recommend that you upgrade your moin packages.");

  script_tag(name:"affected", value:"'moin' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"moinmoin-common", ver:"1.5.3-1.2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.3-1.2etch2", rls:"DEB4"))) {
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
