# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63856");
  script_cve_id("CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0583", "CVE-2009-0584", "CVE-2009-0792");
  script_tag(name:"creation_date", value:"2009-04-20 21:45:17 +0000 (Mon, 20 Apr 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-757-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-757-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-757-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript, gs-esp, gs-gpl' package(s) announced via the USN-757-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript contained a buffer underflow in its
CCITTFax decoding filter. If a user or automated system were tricked into
opening a crafted PDF file, an attacker could cause a denial of service or
execute arbitrary code with privileges of the user invoking the program.
(CVE-2007-6725)

It was discovered that Ghostscript contained a buffer overflow in the
BaseFont writer module. If a user or automated system were tricked into
opening a crafted Postscript file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking the
program. (CVE-2008-6679)

It was discovered that Ghostscript contained additional integer overflows
in its ICC color management library. If a user or automated system were
tricked into opening a crafted Postscript or PDF file, an attacker could
cause a denial of service or execute arbitrary code with privileges of the
user invoking the program. (CVE-2009-0792)

Alin Rad Pop discovered that Ghostscript contained a buffer overflow in the
jbig2dec library. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause a denial of service or execute
arbitrary code with privileges of the user invoking the program.
(CVE-2009-0196)

USN-743-1 provided updated ghostscript and gs-gpl packages to fix two
security vulnerabilities. This update corrects the same vulnerabilities in
the gs-esp package.

Original advisory details:
 It was discovered that Ghostscript contained multiple integer overflows in
 its ICC color management library. If a user or automated system were
 tricked into opening a crafted Postscript file, an attacker could cause a
 denial of service or execute arbitrary code with privileges of the user
 invoking the program. (CVE-2009-0583)

 It was discovered that Ghostscript did not properly perform bounds
 checking in its ICC color management library. If a user or automated
 system were tricked into opening a crafted Postscript file, an attacker
 could cause a denial of service or execute arbitrary code with privileges
 of the user invoking the program. (CVE-2009-0584)");

  script_tag(name:"affected", value:"'ghostscript, gs-esp, gs-gpl' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gs-esp", ver:"8.15.2.dfsg.0ubuntu1-0ubuntu1.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-gpl", ver:"8.15-4ubuntu3.3", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10"))) {
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
