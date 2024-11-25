# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840375");
  script_cve_id("CVE-2009-2625", "CVE-2009-3560", "CVE-2009-3720");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:05 +0000 (Fri, 22 Jan 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-890-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-890-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the USN-890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jukka Taimisto, Tero Rontti and Rauli Kaksonen discovered that Expat did
not properly process malformed XML. If a user or application linked against
Expat were tricked into opening a crafted XML file, an attacker could cause
a denial of service via application crash. (CVE-2009-2625, CVE-2009-3720)

It was discovered that Expat did not properly process malformed UTF-8
sequences. If a user or application linked against Expat were tricked into
opening a crafted XML file, an attacker could cause a denial of service via
application crash. (CVE-2009-3560)");

  script_tag(name:"affected", value:"'expat' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"1.95.8-3ubuntu0.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"1.95.8-3ubuntu0.1", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lib64expat1", ver:"2.0.1-0ubuntu1.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.0.1-0ubuntu1.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"2.0.1-0ubuntu1.1", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lib64expat1", ver:"2.0.1-4ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.0.1-4ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"2.0.1-4ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lib64expat1", ver:"2.0.1-4ubuntu0.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.0.1-4ubuntu0.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"2.0.1-4ubuntu0.9.04.1", rls:"UBUNTU9.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lib64expat1", ver:"2.0.1-4ubuntu1.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.0.1-4ubuntu1.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1-udeb", ver:"2.0.1-4ubuntu1.1", rls:"UBUNTU9.10"))) {
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
