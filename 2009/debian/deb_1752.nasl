# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63683");
  script_cve_id("CVE-2009-0364");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1752)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1752");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1752");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1752");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webcit' package(s) announced via the DSA-1752 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wilfried Goesgens discovered that WebCit, the web-based user interface for the Citadel groupware system, contains a format string vulnerability in the mini_calendar component, possibly allowing arbitrary code execution (CVE-2009-0364).

For the stable distribution (lenny), this problem has been fixed in version 7.37-dfsg-7.

For the unstable distribution (sid), this problem has been fixed in version 7.38b-dfsg-2.

We recommend that you upgrade your webcit packages.");

  script_tag(name:"affected", value:"'webcit' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"citadel-webcit", ver:"7.37-dfsg-7", rls:"DEB5"))) {
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
