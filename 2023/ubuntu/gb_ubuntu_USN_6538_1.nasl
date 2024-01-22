# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6538.1");
  script_cve_id("CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"creation_date", value:"2023-12-07 04:08:46 +0000 (Thu, 07 Dec 2023)");
  script_version("2023-12-15T05:06:25+0000");
  script_tag(name:"last_modification", value:"2023-12-15 05:06:25 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 22:15:00 +0000 (Wed, 13 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6538-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6538-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6538-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-12, postgresql-14, postgresql-15' package(s) announced via the USN-6538-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jingzhou Fu discovered that PostgreSQL incorrectly handled certain unknown
arguments in aggregate function calls. A remote attacker could possibly use
this issue to obtain sensitive information. (CVE-2023-5868)

Pedro Gallegos discovered that PostgreSQL incorrectly handled modifying
certain SQL array values. A remote attacker could use this issue to obtain
sensitive information, or possibly execute arbitrary code. (CVE-2023-5869)

Hemanth Sandrana and Mahendrakar Srinivasarao discovered that PostgreSQL
allowed the pg_signal_backend role to signal certain superuser processes,
contrary to expectations. (CVE-2023-5870)");

  script_tag(name:"affected", value:"'postgresql-12, postgresql-14, postgresql-15' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-12", ver:"12.17-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-12", ver:"12.17-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-14", ver:"14.10-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-14", ver:"14.10-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-15", ver:"15.5-0ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-15", ver:"15.5-0ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-15", ver:"15.5-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-15", ver:"15.5-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
