# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5966.2");
  script_cve_id("CVE-2022-37703", "CVE-2022-37704", "CVE-2022-37705");
  script_tag(name:"creation_date", value:"2023-03-24 04:11:00 +0000 (Fri, 24 Mar 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-28 18:24:00 +0000 (Fri, 28 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-5966-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5966-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5966-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2012536");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'amanda' package(s) announced via the USN-5966-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5966-1 fixed vulnerabilities in amanda. Unfortunately it introduced
a regression in GNUTAR-based backups. This update reverts all of the
changes in amanda until a better fix is provided.

We apologize for the inconvenience.

Original advisory details:

 Maher Azzouzi discovered an information disclosure vulnerability in the
 calcsize binary within amanda. calcsize is a suid binary owned by root that
 could possibly be used by a malicious local attacker to expose sensitive
 file system information. (CVE-2022-37703)

 Maher Azzouzi discovered a privilege escalation vulnerability in the
 rundump binary within amanda. rundump is a suid binary owned by root that
 did not perform adequate sanitization of environment variables or
 commandline options and could possibly be used by a malicious local
 attacker to escalate privileges. (CVE-2022-37704)

 Maher Azzouzi discovered a privilege escalation vulnerability in the runtar
 binary within amanda. runtar is a suid binary owned by root that did not
 perform adequate sanitization of commandline options and could possibly be
 used by a malicious local attacker to escalate privileges. (CVE-2022-37705)");

  script_tag(name:"affected", value:"'amanda' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.3.3-2ubuntu1.1+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.3.6-4.1ubuntu0.1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-1ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-2ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-8ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-9ubuntu0.2", rls:"UBUNTU22.10"))) {
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
