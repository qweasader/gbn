# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6885.2");
  script_cve_id("CVE-2024-36387", "CVE-2024-38473", "CVE-2024-38474", "CVE-2024-38475", "CVE-2024-38476", "CVE-2024-38477", "CVE-2024-39573", "CVE-2024-39884");
  script_tag(name:"creation_date", value:"2024-07-12 04:07:54 +0000 (Fri, 12 Jul 2024)");
  script_version("2024-08-22T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-22 05:05:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-21 15:08:56 +0000 (Wed, 21 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-6885-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6885-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6885-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2072648");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-6885-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6885-1 fixed vulnerabilities in Apache HTTP Server. One of the security
fixes introduced a regression when proxying requests to a HTTP/2 server.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Marc Stern discovered that the Apache HTTP Server incorrectly handled
 serving WebSocket protocol upgrades over HTTP/2 connections. A remote
 attacker could possibly use this issue to cause the server to crash,
 resulting in a denial of service. (CVE-2024-36387)

 Orange Tsai discovered that the Apache HTTP Server mod_proxy module
 incorrectly sent certain request URLs with incorrect encodings to backends.
 A remote attacker could possibly use this issue to bypass authentication.
 (CVE-2024-38473)

 Orange Tsai discovered that the Apache HTTP Server mod_rewrite module
 incorrectly handled certain substitutions. A remote attacker could possibly
 use this issue to execute scripts in directories not directly reachable
 by any URL, or cause a denial of service. Some environments may require
 using the new UnsafeAllow3F flag to handle unsafe substitutions.
 (CVE-2024-38474, CVE-2024-38475, CVE-2024-39573)

 Orange Tsai discovered that the Apache HTTP Server incorrectly handled
 certain response headers. A remote attacker could possibly use this issue
 to obtain sensitive information, execute local scripts, or perform SSRF
 attacks. (CVE-2024-38476)

 Orange Tsai discovered that the Apache HTTP Server mod_proxy module
 incorrectly handled certain requests. A remote attacker could possibly use
 this issue to cause the server to crash, resulting in a denial of service.
 (CVE-2024-38477)

 It was discovered that the Apache HTTP Server incorrectly handled certain
 handlers configured via AddType. A remote attacker could possibly use this
 issue to obtain source code. (CVE-2024-39884)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.20", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.52-1ubuntu4.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.58-1ubuntu8.3", rls:"UBUNTU24.04 LTS"))) {
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
