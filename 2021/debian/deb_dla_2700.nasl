# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892700");
  script_cve_id("CVE-2019-19630", "CVE-2021-20308", "CVE-2021-23158", "CVE-2021-23165", "CVE-2021-23180", "CVE-2021-23191", "CVE-2021-23206", "CVE-2021-26252", "CVE-2021-26259", "CVE-2021-26948");
  script_tag(name:"creation_date", value:"2021-07-01 03:00:36 +0000 (Thu, 01 Jul 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 17:01:00 +0000 (Tue, 22 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-2700-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2700-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2700-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/htmldoc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'htmldoc' package(s) announced via the DLA-2700-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in HTMLDOC, a HTML processor that generates indexed HTML, PS, and PDF, which could potentially result in the execution of arbitrary code. In addition a number of crashes were addressed.

For Debian 9 stretch, these problems have been fixed in version 1.8.27-8+deb9u1.

We recommend that you upgrade your htmldoc packages.

For the detailed security status of htmldoc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'htmldoc' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"htmldoc", ver:"1.8.27-8+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"htmldoc-common", ver:"1.8.27-8+deb9u1", rls:"DEB9"))) {
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
