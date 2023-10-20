# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703494");
  script_cve_id("CVE-2015-8377", "CVE-2015-8604");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:48 +0000 (Tue, 08 Mar 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:13:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Debian: Security Advisory (DSA-3494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3494");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3494");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3494");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-3494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two SQL injection vulnerabilities were discovered in cacti, a web interface for graphing of monitoring systems. Specially crafted input can be used by an attacker in parameters of the graphs_new.php script to execute arbitrary SQL commands on the database.

For the oldstable distribution (wheezy), these problems have been fixed in version 0.8.8a+dfsg-5+deb7u8.

For the stable distribution (jessie), these problems have been fixed in version 0.8.8b+dfsg-8+deb8u4.

For the testing distribution (stretch), these problems have been fixed in version 0.8.8f+ds1-4.

For the unstable distribution (sid), these problems have been fixed in version 0.8.8f+ds1-4.

We recommend that you upgrade your cacti packages.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8a+dfsg-5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8b+dfsg-8+deb8u4", rls:"DEB8"))) {
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
