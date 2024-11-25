# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844723");
  script_cve_id("CVE-2020-16012", "CVE-2020-26951", "CVE-2020-26952", "CVE-2020-26953", "CVE-2020-26956", "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26961", "CVE-2020-26962", "CVE-2020-26963", "CVE-2020-26965", "CVE-2020-26967", "CVE-2020-26968", "CVE-2020-26969");
  script_tag(name:"creation_date", value:"2020-11-20 04:00:53 +0000 (Fri, 20 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-10 18:35:08 +0000 (Thu, 10 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4637-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4637-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4637-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-4637-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4637-1 fixed vulnerabilities in Firefox. This update provides the
corresponding updates for Ubuntu 16.04 LTS.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across origins, bypass security restrictions, conduct phishing
 attacks, conduct cross-site scripting (XSS) attacks, bypass Content
 Security Policy (CSP) restrictions, conduct DNS rebinding attacks, or
 execute arbitrary code.");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"83.0+build2-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
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
