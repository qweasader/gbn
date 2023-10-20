# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5810.2");
  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_tag(name:"creation_date", value:"2023-01-20 04:10:35 +0000 (Fri, 20 Jan 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-25 14:32:00 +0000 (Wed, 25 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5810-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5810-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5810-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2003246");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the USN-5810-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5810-1 fixed vulnerabilities in Git. This update introduced a regression as it
was missing some commit lines. This update fixes the problem.

Original advisory details:

 Markus Vervier and Eric Sesterhenn discovered that Git incorrectly handled certain
 gitattributes. An attacker could possibly use this issue to cause a crash
 or execute arbitrary code. (CVE-2022-23521)

 Joern Schneeweisz discovered that Git incorrectly handled certain commands.
 An attacker could possibly use this issue to cause a crash or execute
 arbitrary code. (CVE-2022-41903)");

  script_tag(name:"affected", value:"'git' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.17.1-1ubuntu0.15", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.25.1-1ubuntu3.8", rls:"UBUNTU20.04 LTS"))) {
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
