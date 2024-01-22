# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705107");
  script_cve_id("CVE-2022-23614");
  script_tag(name:"creation_date", value:"2022-03-25 02:00:05 +0000 (Fri, 25 Mar 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-10 13:58:00 +0000 (Thu, 10 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5107-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5107-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5107-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5107");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php-twig");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-twig' package(s) announced via the DSA-5107-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marlon Starkloff discovered that twig, a template engine for PHP, did not correctly enforce sandboxing. This would allow a malicious user to execute arbitrary code.

For the stable distribution (bullseye), this problem has been fixed in version 2.14.3-1+deb11u1.

We recommend that you upgrade your php-twig packages.

For the detailed security status of php-twig please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php-twig' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"php-twig", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-cssinliner-extra", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-doc", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-extra-bundle", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-html-extra", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-inky-extra", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-intl-extra", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-twig-markdown-extra", ver:"2.14.3-1+deb11u1", rls:"DEB11"))) {
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
