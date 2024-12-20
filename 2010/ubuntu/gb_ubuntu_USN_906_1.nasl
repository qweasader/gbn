# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840396");
  script_cve_id("CVE-2009-3553", "CVE-2010-0302", "CVE-2010-0393");
  script_tag(name:"creation_date", value:"2010-03-05 11:48:43 +0000 (Fri, 05 Mar 2010)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:22:17 +0000 (Sat, 03 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-906-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-906-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-906-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups, cupsys' package(s) announced via the USN-906-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CUPS scheduler did not properly handle certain
network operations. A remote attacker could exploit this flaw and cause the
CUPS server to crash, resulting in a denial of service. This issue only
affected Ubuntu 8.04 LTS, 8.10, 9.04 and 9.10. (CVE-2009-3553,
CVE-2010-0302)

Ronald Volgers discovered that the CUPS lppasswd tool could be made to load
localized message strings from arbitrary files by setting an environment
variable. A local attacker could exploit this with a format-string
vulnerability leading to a root privilege escalation. The default compiler
options for Ubuntu 8.10, 9.04 and 9.10 should reduce this vulnerability to
a denial of service. (CVE-2010-0393)");

  script_tag(name:"affected", value:"'cups, cupsys' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.2-0ubuntu0.6.06.17", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cupsys-client", ver:"1.2.2-0ubuntu0.6.06.17", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.3.7-1ubuntu3.8", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cupsys-client", ver:"1.3.7-1ubuntu3.8", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"1.3.9-2ubuntu9.5", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"1.3.9-2ubuntu9.5", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"1.3.9-17ubuntu3.6", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"1.3.9-17ubuntu3.6", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"1.4.1-5ubuntu2.4", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"1.4.1-5ubuntu2.4", rls:"UBUNTU9.10"))) {
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
