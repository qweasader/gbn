# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53721");
  script_cve_id("CVE-2002-1378", "CVE-2002-1379", "CVE-2002-1508");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-227");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-227");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-227");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openldap2' package(s) announced via the DSA-227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SuSE Security Team reviewed critical parts of openldap2, an implementation of the Lightweight Directory Access Protocol (LDAP) version 2 and 3, and found several buffer overflows and other bugs remote attackers could exploit to gain access on systems running vulnerable LDAP servers. In addition to these bugs, various local exploitable bugs within the OpenLDAP2 libraries have been fixed.

For the current stable distribution (woody) these problems have been fixed in version 2.0.23-6.3.

The old stable distribution (potato) does not contain OpenLDAP2 packages.

For the unstable distribution (sid) these problems have been fixed in version 2.0.27-3.

We recommend that you upgrade your openldap2 packages.");

  script_tag(name:"affected", value:"'openldap2' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"ldap-gateways", ver:"2.0.23-6.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.0.23-6.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap2", ver:"2.0.23-6.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.0.23-6.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.0.23-6.3", rls:"DEB3.0"))) {
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
