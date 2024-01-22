# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703071");
  script_cve_id("CVE-2014-1544");
  script_tag(name:"creation_date", value:"2014-11-10 23:00:00 +0000 (Mon, 10 Nov 2014)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3071-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3071-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3071");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-3071-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In nss, a set of libraries designed to support cross-platform development of security-enabled client and server applications, Tyson Smith and Jesse Schwartzentruber discovered a use-after-free vulnerability that allows remote attackers to execute arbitrary code by triggering the improper removal of an NSSCertificate structure from a trust domain.

For the stable distribution (wheezy), this problem has been fixed in version 2:3.14.5-1+deb7u3.

For the upcoming stable distribution (jessie), this problem has been fixed in version 2:3.16.3-1.

For the unstable distribution (sid), this problem has been fixed in version 2:3.16.3-1.

We recommend that you upgrade your nss packages.");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.14.5-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"2:3.14.5-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dbg", ver:"2:3.14.5-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"2:3.14.5-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"2:3.14.5-1+deb7u3", rls:"DEB7"))) {
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
