# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843118");
  script_cve_id("CVE-2017-5029", "CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5033", "CVE-2017-5035", "CVE-2017-5037", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046");
  script_tag(name:"creation_date", value:"2017-03-30 04:32:20 +0000 (Thu, 30 Mar 2017)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-28 18:04:03 +0000 (Fri, 28 Apr 2017)");

  script_name("Ubuntu: Security Advisory (USN-3236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3236-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3236-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-3236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to obtain sensitive information, spoof
application UI by causing the security status API or webview URL to
indicate the wrong values, bypass security restrictions, cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2017-5029, CVE-2017-5030, CVE-2017-5031, CVE-2017-5033,
CVE-2017-5035, CVE-2017-5037, CVE-2017-5040, CVE-2017-5041, CVE-2017-5044,
CVE-2017-5045, CVE-2017-5046)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.21.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.21.5-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.21.5-0ubuntu0.16.10.1", rls:"UBUNTU16.10"))) {
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
