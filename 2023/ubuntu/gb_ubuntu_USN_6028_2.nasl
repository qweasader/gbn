# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6028.2");
  script_cve_id("CVE-2022-2309", "CVE-2023-28484", "CVE-2023-29469");
  script_tag(name:"creation_date", value:"2023-06-08 04:09:39 +0000 (Thu, 08 Jun 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 01:44:28 +0000 (Wed, 13 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-6028-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.04");

  script_xref(name:"Advisory-ID", value:"USN-6028-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6028-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-6028-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6028-1 fixed vulnerabilities in libxml2. This update provides the
corresponding updates for Ubuntu 23.04.

Original advisory details:

 It was discovered that libxml2 incorrectly handled certain XML files.
 An attacker could possibly use this issue to cause a crash.
 (CVE-2022-2309)

 It was discovered that lixml2 incorrectly handled certain XML files.
 An attacker could possibly use this issue to cause a crash or execute
 arbitrary code. (CVE-2023-28484)

 It was discovered that libxml2 incorrectly handled certain XML files.
 An attacker could possibly use this issue to cause a crash.
 (CVE-2023-29469)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 23.04.");

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

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.14+dfsg-1.1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.14+dfsg-1.1ubuntu0.1", rls:"UBUNTU23.04"))) {
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
