# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6583.1");
  script_cve_id("CVE-2023-22028", "CVE-2023-22084");
  script_tag(name:"creation_date", value:"2024-01-16 09:59:41 +0000 (Tue, 16 Jan 2024)");
  script_version("2024-01-17T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-01-17 05:05:30 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 01:28:00 +0000 (Wed, 18 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6583-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6583-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6583-1");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-44.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.7' package(s) announced via the USN-6583-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.7.44 in Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.7' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.44-0ubuntu0.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.44-0ubuntu0.18.04.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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
