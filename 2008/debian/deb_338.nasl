# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53627");
  script_cve_id("CVE-2003-0500");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-338)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-338");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-338");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-338");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd' package(s) announced via the DSA-338 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"runlevel [runlevel@raregazz.org] reported that ProFTPD's PostgreSQL authentication module is vulnerable to a SQL injection attack. This vulnerability could be exploited by a remote, unauthenticated attacker to execute arbitrary SQL statements, potentially exposing the passwords of other users, or to connect to ProFTPD as an arbitrary user without supplying the correct password.

For the stable distribution (woody) this problem has been fixed in version 1.2.4+1.2.5rc1-5woody2.

For the unstable distribution (sid) this problem has been fixed in version 1.2.8-8.

We recommend that you update your proftpd package.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"proftpd", ver:"1.2.4+1.2.5rc1-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-common", ver:"1.2.4+1.2.5rc1-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.2.4+1.2.5rc1-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-ldap", ver:"1.2.4+1.2.5rc1-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mysql", ver:"1.2.4+1.2.5rc1-5woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-pgsql", ver:"1.2.4+1.2.5rc1-5woody2", rls:"DEB3.0"))) {
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
