# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841827");
  script_cve_id("CVE-2014-0107");
  script_tag(name:"creation_date", value:"2014-05-26 10:26:51 +0000 (Mon, 26 May 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2218-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2218-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2218-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxalan2-java' package(s) announced via the USN-2218-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicolas Gregoire discovered that Xalan-Java incorrectly handled certain
properties when the secure processing feature was enabled. An attacker
could possibly use this issue to load arbitrary classes or access external
resources.");

  script_tag(name:"affected", value:"'libxalan2-java' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 13.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxalan2-java", ver:"2.7.1-5ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxalan2-java-gcj", ver:"2.7.1-5ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxsltc-java", ver:"2.7.1-5ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxsltc-java-gcj", ver:"2.7.1-5ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxalan2-java", ver:"2.7.1-7ubuntu0.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxsltc-java", ver:"2.7.1-7ubuntu0.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxalan2-java", ver:"2.7.1-8ubuntu0.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxsltc-java", ver:"2.7.1-8ubuntu0.1", rls:"UBUNTU13.10"))) {
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
