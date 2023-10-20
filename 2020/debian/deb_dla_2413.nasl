# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892413");
  script_cve_id("CVE-2019-19617", "CVE-2020-26934", "CVE-2020-26935");
  script_tag(name:"creation_date", value:"2020-10-26 04:00:22 +0000 (Mon, 26 Oct 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-30 22:15:00 +0000 (Tue, 30 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-2413)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2413");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2413");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/phpmyadmin");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DLA-2413 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in package phpmyadmin.

CVE-2019-19617

phpMyAdmin does not escape certain Git information, related to libraries/classes/Display/GitRevision.php and libraries/classes /Footer.php.

CVE-2020-26934

A vulnerability was discovered where an attacker can cause an XSS attack through the transformation feature.

If an attacker sends a crafted link to the victim with the malicious JavaScript, when the victim clicks on the link, the JavaScript will run and complete the instructions made by the attacker.

CVE-2020-26935

An SQL injection vulnerability was discovered in how phpMyAdmin processes SQL statements in the search feature. An attacker could use this flaw to inject malicious SQL in to a query.

For Debian 9 stretch, these problems have been fixed in version 4.6.6-4+deb9u2.

We recommend that you upgrade your phpmyadmin packages.

For the detailed security status of phpmyadmin please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.6.6-4+deb9u2", rls:"DEB9"))) {
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
