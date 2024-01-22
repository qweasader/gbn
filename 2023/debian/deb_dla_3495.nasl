# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3495");
  script_cve_id("CVE-2021-3838", "CVE-2022-2400");
  script_tag(name:"creation_date", value:"2023-07-14 04:30:52 +0000 (Fri, 14 Jul 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-23 02:21:00 +0000 (Sat, 23 Jul 2022)");

  script_name("Debian: Security Advisory (DLA-3495-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3495-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3495-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php-dompdf");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-dompdf' package(s) announced via the DLA-3495-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilies were fixed in php-dompdf a CSS 2.1 compliant HTML to PDF converter, written in PHP.

CVE-2021-3838

php-dompdf was vulnerable to deserialization of Untrusted Data using PHAR deserialization (phar://) as url for image.

CVE-2022-2400

php-dompdf was vulnerable to External Control of File Name bypassing unallowed access verification.

For Debian 10 buster, these problems have been fixed in version 0.6.2+dfsg-3+deb10u1.

We recommend that you upgrade your php-dompdf packages.

For the detailed security status of php-dompdf please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php-dompdf' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-dompdf", ver:"0.6.2+dfsg-3+deb10u1", rls:"DEB10"))) {
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
