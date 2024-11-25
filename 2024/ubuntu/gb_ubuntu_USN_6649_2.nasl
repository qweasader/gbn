# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6649.2");
  script_cve_id("CVE-2024-1546", "CVE-2024-1547", "CVE-2024-1548", "CVE-2024-1549", "CVE-2024-1550", "CVE-2024-1551", "CVE-2024-1552", "CVE-2024-1553", "CVE-2024-1554", "CVE-2024-1555", "CVE-2024-1556", "CVE-2024-1557");
  script_tag(name:"creation_date", value:"2024-03-06 08:59:21 +0000 (Wed, 06 Mar 2024)");
  script_version("2024-03-07T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-03-07 05:06:18 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6649-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6649-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6649-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2056258");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6649-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6649-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2024-1547,
 CVE-2024-1548, CVE-2024-1549, CVE-2024-1550, CVE-2024-1553, CVE-2024-1554,
 CVE-2024-1555, CVE-2024-1557)

 Alfred Peters discovered that Firefox did not properly manage memory when
 storing and re-accessing data on a networking channel. An attacker could
 potentially exploit this issue to cause a denial of service.
 (CVE-2024-1546)

 Johan Carlsson discovered that Firefox incorrectly handled Set-Cookie
 response headers in multipart HTTP responses. An attacker could
 potentially exploit this issue to inject arbitrary cookie values.
 (CVE-2024-1551)

 Gary Kwong discovered that Firefox incorrectly generated codes on 32-bit
 ARM devices, which could lead to unexpected numeric conversions or
 undefined behaviour. An attacker could possibly use this issue to cause a
 denial of service. (CVE-2024-1552)

 Ronald Crane discovered that Firefox did not properly manage memory when
 accessing the built-in profiler. An attacker could potentially exploit
 this issue to cause a denial of service. (CVE-2024-1556)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"123.0.1+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
