# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3529");
  script_cve_id("CVE-2021-23445");
  script_tag(name:"creation_date", value:"2023-08-16 04:24:34 +0000 (Wed, 16 Aug 2023)");
  script_version("2023-08-16T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-08-16 05:05:28 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 15:45:00 +0000 (Tue, 12 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-3529)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3529");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3529");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/datatables.js");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'datatables.js' package(s) announced via the DLA-3529 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"datatables.js is a jQuery plug-in that makes nice tables from different data sources.

It was discovered that if an array is passed to the HTML escape entities function, it would not have its contents escaped.

For Debian 10 buster, this problem has been fixed in version 1.10.19+dfsg-1+deb10u1.

We recommend that you upgrade your datatables.js packages.

For the detailed security status of datatables.js please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'datatables.js' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-datatables", ver:"1.10.19+dfsg-1+deb10u1", rls:"DEB10"))) {
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