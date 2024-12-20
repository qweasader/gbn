# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5954.2");
  script_cve_id("CVE-2023-25750", "CVE-2023-25751", "CVE-2023-25752", "CVE-2023-28160", "CVE-2023-28161", "CVE-2023-28162", "CVE-2023-28164", "CVE-2023-28176", "CVE-2023-28177");
  script_tag(name:"creation_date", value:"2023-03-28 00:20:39 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-09 03:57:08 +0000 (Fri, 09 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-5954-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5954-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5954-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2012696");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5954-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5954-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2023-25750,
 CVE-2023-25752, CVE-2023-28162, CVE-2023-28176, CVE-2023-28177)

 Lukas Bernhard discovered that Firefox did not properly manage memory
 when invalidating JIT code while following an iterator. An attacker could
 potentially exploits this issue to cause a denial of service.
 (CVE-2023-25751)

 Rob Wu discovered that Firefox did not properly manage the URLs when
 following a redirect to a publicly accessible web extension file. An
 attacker could potentially exploits this to obtain sensitive information.
 (CVE-2023-28160)

 Luan Herrera discovered that Firefox did not properly manage cross-origin
 iframe when dragging a URL. An attacker could potentially exploit this
 issue to perform spoofing attacks. (CVE-2023-28164)

 Khiem Tran discovered that Firefox did not properly manage one-time
 permissions granted to a document loaded using a file: URL. An attacker
 could potentially exploit this issue to use granted one-time permissions
 on the local files came from different sources. (CVE-2023-28161)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"111.0.1+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"111.0.1+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
