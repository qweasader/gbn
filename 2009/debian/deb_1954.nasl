# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66592");
  script_cve_id("CVE-2007-3112", "CVE-2007-3113", "CVE-2009-4032");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1954)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1954");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1954");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1954");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-1954 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in cacti, a frontend to rrdtool for monitoring systems and services. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3112, CVE-2007-3113 It was discovered that cacti is prone to a denial of service via the graph_height, graph_width, graph_start and graph_end parameters. This issue only affects the oldstable (etch) version of cacti.

CVE-2009-4032

It was discovered that cacti is prone to several cross-site scripting attacks via different vectors.

CVE-2009-4112

It has been discovered that cacti allows authenticated administrator users to gain access to the host system by executing arbitrary commands via the 'Data Input Method' for the 'Linux - Get Memory Usage' setting.

There is no fix for this issue at this stage. Upstream will implement a whitelist policy to only allow certain 'safe' commands. For the moment, we recommend that such access is only given to trusted users and that the options 'Data Input' and 'User Administration' are otherwise deactivated.

For the oldstable distribution (etch), these problems have been fixed in version 0.8.6i-3.6.

For the stable distribution (lenny), this problem has been fixed in version 0.8.7b-2.1+lenny1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 0.8.7e-1.1.

We recommend that you upgrade your cacti packages.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.6i-3.6", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.7b-2.1+lenny1", rls:"DEB5"))) {
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
