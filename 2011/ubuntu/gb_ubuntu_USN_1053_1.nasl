# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840580");
  script_cve_id("CVE-2007-2448", "CVE-2010-3315", "CVE-2010-4539", "CVE-2010-4644");
  script_tag(name:"creation_date", value:"2011-02-04 13:19:53 +0000 (Fri, 04 Feb 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|6\.06\ LTS|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1053-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1053-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the USN-1053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Subversion incorrectly handled certain 'partial
access' privileges in rare scenarios. Remote authenticated users could use
this flaw to obtain sensitive information (revision properties). This issue
only applied to Ubuntu 6.06 LTS. (CVE-2007-2448)

It was discovered that the Subversion mod_dav_svn module for Apache did not
properly handle a named repository as a rule scope. Remote authenticated
users could use this flaw to bypass intended restrictions. This issue only
applied to Ubuntu 9.10, 10.04 LTS, and 10.10. (CVE-2010-3315)

It was discovered that the Subversion mod_dav_svn module for Apache
incorrectly handled the walk function. Remote authenticated users could use
this flaw to cause the service to crash, leading to a denial of service.
(CVE-2010-4539)

It was discovered that Subversion incorrectly handled certain memory
operations. Remote authenticated users could use this flaw to consume large
quantities of memory and cause the service to crash, leading to a denial of
service. This issue only applied to Ubuntu 9.10, 10.04 LTS, and 10.10.
(CVE-2010-4644)");

  script_tag(name:"affected", value:"'subversion' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.6dfsg-2ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.6dfsg-2ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.12dfsg-1ubuntu1.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.12dfsg-1ubuntu1.1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.3.1-3ubuntu1.3", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn0", ver:"1.3.1-3ubuntu1.3", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.4.6dfsg1-2ubuntu1.2", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.4.6dfsg1-2ubuntu1.2", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.5dfsg-1ubuntu1.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.5dfsg-1ubuntu1.1", rls:"UBUNTU9.10"))) {
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
