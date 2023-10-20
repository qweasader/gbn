# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840521");
  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|6\.06\ LTS|8\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1005-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1005-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-1005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that poppler contained multiple security issues when
parsing malformed PDF documents. If a user or automated system were tricked
into opening a crafted PDF file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking the
program.");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib4", ver:"0.12.4-0ubuntu5.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler5", ver:"0.12.4-0ubuntu5.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib5", ver:"0.14.3-0ubuntu1.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler7", ver:"0.14.3-0ubuntu1.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler1", ver:"0.5.1-0ubuntu7.8", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler1-glib", ver:"0.5.1-0ubuntu7.8", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib2", ver:"0.6.4-1ubuntu3.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler2", ver:"0.6.4-1ubuntu3.5", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib4", ver:"0.10.5-1ubuntu2.6", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler4", ver:"0.10.5-1ubuntu2.6", rls:"UBUNTU9.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib4", ver:"0.12.0-0ubuntu2.3", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler5", ver:"0.12.0-0ubuntu2.3", rls:"UBUNTU9.10"))) {
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
