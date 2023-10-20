# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3440");
  script_cve_id("CVE-2023-32324");
  script_tag(name:"creation_date", value:"2023-06-05 04:21:35 +0000 (Mon, 05 Jun 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 14:32:00 +0000 (Thu, 08 Jun 2023)");

  script_name("Debian: Security Advisory (DLA-3440)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3440");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3440");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cups");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DLA-3440 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in cups, the Common UNIX Printing System. Due to a buffer overflow vulnerability in the function format_log_line() a remote attackers could cause a denial-of-service(DoS). The vulnerability can be triggered when the configuration file cupsd.conf sets the value of loglevel to DEBUG.

For Debian 10 buster, this problem has been fixed in version 2.2.10-6+deb10u7.

We recommend that you upgrade your cups packages.

For the detailed security status of cups please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-bsd", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-common", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-core-drivers", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ipp-utils", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ppdc", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-server-common", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2-dev", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"2.2.10-6+deb10u7", rls:"DEB10"))) {
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
