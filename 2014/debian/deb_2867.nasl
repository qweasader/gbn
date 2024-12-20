# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702867");
  script_cve_id("CVE-2014-1471", "CVE-2014-1694");
  script_tag(name:"creation_date", value:"2014-02-22 23:00:00 +0000 (Sat, 22 Feb 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2867-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2867-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2867");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs2' package(s) announced via the DSA-2867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in otrs2, the Open Ticket Request System. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-1694

Norihiro Tanaka reported missing challenge token checks. An attacker that managed to take over the session of a logged in customer could create tickets and/or send follow-ups to existing tickets due to these missing checks.

CVE-2014-1471

Karsten Nielsen from Vasgard GmbH discovered that an attacker with a valid customer or agent login could inject SQL code through the ticket search URL.

For the oldstable distribution (squeeze), these problems have been fixed in version 2.4.9+dfsg1-3+squeeze5.

For the stable distribution (wheezy), these problems have been fixed in version 3.1.7+dfsg1-8+deb7u4.

For the testing distribution (jessie) and the unstable distribution (sid), these problems have been fixed in version 3.3.4-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"2.4.9+dfsg1-3+squeeze5", rls:"DEB6"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"3.1.7+dfsg1-8+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"3.1.7+dfsg1-8+deb7u4", rls:"DEB7"))) {
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
