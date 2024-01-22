# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703209");
  script_cve_id("CVE-2013-4449", "CVE-2014-9713", "CVE-2015-1545");
  script_tag(name:"creation_date", value:"2015-03-29 22:00:00 +0000 (Sun, 29 Mar 2015)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3209-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3209-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3209-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3209");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openldap' package(s) announced via the DSA-3209-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in OpenLDAP, a free implementation of the Lightweight Directory Access Protocol.

CVE-2013-4449

Michael Vishchers from Seven Principles AG discovered a denial of service vulnerability in slapd, the directory server implementation. When the server is configured to used the RWM overlay, an attacker can make it crash by unbinding just after connecting, because of an issue with reference counting.

CVE-2014-9713

The default Debian configuration of the directory database allows every users to edit their own attributes. When LDAP directories are used for access control, and this is done using user attributes, an authenticated user can leverage this to gain access to unauthorized resources.

Please note this is a Debian specific vulnerability.

The new package won't use the unsafe access control rule for new databases, but existing configurations won't be automatically modified. Administrators are incited to look at the README.Debian file provided by the updated package if they need to fix the access control rule.

CVE-2015-1545

Ryan Tandy discovered a denial of service vulnerability in slapd. When using the deref overlay, providing an empty attribute list in a query makes the daemon crashes.

For the stable distribution (wheezy), these problems have been fixed in version 2.4.31-2.

For the upcoming stable distribution (jessie), these problems have been fixed in version 2.4.40-4.

For the unstable distribution (sid), these problems have been fixed in version 2.4.40-4.

We recommend that you upgrade your openldap packages.");

  script_tag(name:"affected", value:"'openldap' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.31-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.31-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2-dbg", ver:"2.4.31-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.31-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.31-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-dbg", ver:"2.4.31-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-smbk5pwd", ver:"2.4.31-2", rls:"DEB7"))) {
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
