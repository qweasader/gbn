# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702733");
  script_cve_id("CVE-2013-4717");
  script_tag(name:"creation_date", value:"2013-08-01 22:00:00 +0000 (Thu, 01 Aug 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 15:32:00 +0000 (Tue, 17 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-2733)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2733");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2733");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2733");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs2' package(s) announced via the DSA-2733 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that otrs2, the Open Ticket Request System, does not properly sanitise user-supplied data that is used on SQL queries. An attacker with a valid agent login could exploit this issue to craft SQL queries by injecting arbitrary SQL code through manipulated URLs.

For the oldstable distribution (squeeze), this problem has been fixed in version 2.4.9+dfsg1-3+squeeze4. This update also provides fixes for CVE-2012-4751, CVE-2013-2625 and CVE-2013-4088, which were all fixed for stable already.

For the stable distribution (wheezy), this problem has been fixed in version 3.1.7+dfsg1-8+deb7u3.

For the testing distribution (jessie), this problem has been fixed in version 3.2.9-1.

For the unstable distribution (sid), this problem has been fixed in version 3.2.9-1.

We recommend that you upgrade your otrs2 packages.");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"2.4.9+dfsg1-3+squeeze4", rls:"DEB6"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"3.1.7+dfsg1-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"3.1.7+dfsg1-8+deb7u3", rls:"DEB7"))) {
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
