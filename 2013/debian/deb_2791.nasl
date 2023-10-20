# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702791");
  script_cve_id("CVE-2013-4510");
  script_tag(name:"creation_date", value:"2013-11-03 23:00:00 +0000 (Sun, 03 Nov 2013)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_name("Debian: Security Advisory (DSA-2791)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2791");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2791");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2791");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tryton-client' package(s) announced via the DSA-2791 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cedric Krier discovered that the Tryton client does not sanitize the file extension supplied by the server when processing reports. As a result, a malicious server could send a report with a crafted file extension that causes the client to write any local file to which the user running the client has write access.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.6.1-1+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in version 2.2.3-1+deb7u1.

We recommend that you upgrade your tryton-client packages.");

  script_tag(name:"affected", value:"'tryton-client' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"tryton-client", ver:"1.6.1-1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"tryton-client", ver:"2.2.3-1+deb7u1", rls:"DEB7"))) {
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
