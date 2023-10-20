# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64574");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-810-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-810-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-810-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/387745");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr' package(s) announced via the USN-810-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-810-1 fixed vulnerabilities in NSS. This update provides the NSPR
needed to use the new NSS.

Original advisory details:

 Moxie Marlinspike discovered that NSS did not properly handle regular
 expressions in certificate names. A remote attacker could create a
 specially crafted certificate to cause a denial of service (via application
 crash) or execute arbitrary code as the user invoking the program.
 (CVE-2009-2404)

 Moxie Marlinspike and Dan Kaminsky independently discovered that NSS did
 not properly handle certificates with NULL characters in the certificate
 name. An attacker could exploit this to perform a machine-in-the-middle attack
 to view sensitive information or alter encrypted communications.
 (CVE-2009-2408)

 Dan Kaminsky discovered NSS would still accept certificates with MD2 hash
 signatures. As a result, an attacker could potentially create a malicious
 trusted certificate to impersonate another site. (CVE-2009-2409)");

  script_tag(name:"affected", value:"'nspr' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.7.5-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.7.5-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.7.5-0ubuntu0.9.04.1", rls:"UBUNTU9.04"))) {
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
