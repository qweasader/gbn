# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703075");
  script_cve_id("CVE-2014-9015", "CVE-2014-9016");
  script_tag(name:"creation_date", value:"2014-11-19 23:00:00 +0000 (Wed, 19 Nov 2014)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3075)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3075");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3075");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3075");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-3075 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Drupal, a fully-featured content management framework. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2014-9015

Aaron Averill discovered that a specially crafted request can give a user access to another user's session, allowing an attacker to hijack a random session.

CVE-2014-9016

Michael Cullum, Javier Nieto and Andres Rojas Guerrero discovered that the password hashing API allows an attacker to send specially crafted requests resulting in CPU and memory exhaustion. This may lead to the site becoming unavailable or unresponsive (denial of service).

Custom configured session.inc and password.inc need to be audited as well to verify if they are prone to these vulnerabilities. More information can be found in the upstream advisory at

For the stable distribution (wheezy), these problems have been fixed in version 7.14-2+deb7u8.

We recommend that you upgrade your drupal7 packages.");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u8", rls:"DEB7"))) {
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
