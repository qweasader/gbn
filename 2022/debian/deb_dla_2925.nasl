# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892925");
  script_cve_id("CVE-2022-25271");
  script_tag(name:"creation_date", value:"2022-12-02 11:04:57 +0000 (Fri, 02 Dec 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 14:47:00 +0000 (Fri, 25 Feb 2022)");

  script_name("Debian: Security Advisory (DLA-2925)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2925");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2925");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DLA-2925 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security updates includes two fixes, backported respectively from Drupal version 7.87 and 7.88:

- Fix a regression caused by Query ui position() backport in version 7.86 (backported as 7.52-2+deb9u17): was not checking for possible undefined value in options

- Fix improper input validation in Drupal's form API

Drupal is a dynamic web site platform which allows an individual or community of users to publish, manage and organize a variety of content.");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.52-2+deb9u18", rls:"DEB9"))) {
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
