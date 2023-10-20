# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893314");
  script_cve_id("CVE-2019-13616", "CVE-2019-13626", "CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7638", "CVE-2020-14409", "CVE-2020-14410", "CVE-2021-33657", "CVE-2022-4743");
  script_tag(name:"creation_date", value:"2023-02-09 02:00:38 +0000 (Thu, 09 Feb 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 17:49:00 +0000 (Tue, 12 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-3314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3314");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3314");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libsdl2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsdl2' package(s) announced via the DLA-3314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in SDL2, the Simple DirectMedia Layer library. These vulnerabilities may allow an attacker to cause a denial of service or result in the execution of arbitrary code if malformed images or sound files are processed.

For Debian 10 buster, these problems have been fixed in version 2.0.9+dfsg1-1+deb10u1.

We recommend that you upgrade your libsdl2 packages.

For the detailed security status of libsdl2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libsdl2' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsdl2-2.0-0", ver:"2.0.9+dfsg1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl2-dev", ver:"2.0.9+dfsg1-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl2-doc", ver:"2.0.9+dfsg1-1+deb10u1", rls:"DEB10"))) {
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
