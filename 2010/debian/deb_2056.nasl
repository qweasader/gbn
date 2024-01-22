# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67540");
  script_cve_id("CVE-2009-4882", "CVE-2010-2155");
  script_tag(name:"creation_date", value:"2010-06-10 19:49:43 +0000 (Thu, 10 Jun 2010)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2056-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2056-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2056");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zonecheck' package(s) announced via the DSA-2056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that in ZoneCheck, a tool to check DNS configurations, the CGI does not perform sufficient sanitation of user input, an attacker can take advantage of this and pass script code in order to perform cross-site scripting attacks.

For the stable distribution (lenny), this problem has been fixed in version 2.0.4-13lenny1.

For the testing distribution (squeeze), this problem has been fixed in version 2.1.1-1.

For the unstable distribution (sid), this problem has been fixed in version 2.1.1-1.

We recommend that you upgrade your zonecheck packages.");

  script_tag(name:"affected", value:"'zonecheck' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"zonecheck", ver:"2.0.4-13lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zonecheck-cgi", ver:"2.0.4-13lenny1", rls:"DEB5"))) {
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
