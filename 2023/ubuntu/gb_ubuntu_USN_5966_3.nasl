# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5966.3");
  script_cve_id("CVE-2022-37703", "CVE-2022-37704", "CVE-2022-37705");
  script_tag(name:"creation_date", value:"2023-04-03 07:10:12 +0000 (Mon, 03 Apr 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-28 18:24:43 +0000 (Fri, 28 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-5966-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5966-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5966-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2012536");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'amanda' package(s) announced via the USN-5966-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5966-1 fixed vulnerabilities in amanda. Unfortunately that update
caused a regression and was reverted in USN-5966-2. This update provides
security fixes for Ubuntu 22.10, Ubuntu 22.04 LTS, Ubuntu 20.04
LTS and Ubuntu 18.04 LTS.

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

  script_tag(name:"affected", value:"'amanda' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-2ubuntu0.3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-8ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-9ubuntu0.3", rls:"UBUNTU22.10"))) {
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
