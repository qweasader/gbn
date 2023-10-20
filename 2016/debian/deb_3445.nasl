# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703445");
  script_cve_id("CVE-2015-8557");
  script_tag(name:"creation_date", value:"2016-01-12 23:00:00 +0000 (Tue, 12 Jan 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3445)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3445");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3445");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3445");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pygments' package(s) announced via the DSA-3445 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Javantea discovered that pygments, a generic syntax highlighter, is prone to a shell injection vulnerability allowing a remote attacker to execute arbitrary code via shell metacharacters in a font name.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.5+dfsg-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 2.0.1+dfsg-1.1+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 2.0.1+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in version 2.0.1+dfsg-2.

We recommend that you upgrade your pygments packages.");

  script_tag(name:"affected", value:"'pygments' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pygments", ver:"1.5+dfsg-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pygments", ver:"1.5+dfsg-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"python-pygments", ver:"2.0.1+dfsg-1.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pygments-doc", ver:"2.0.1+dfsg-1.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pygments", ver:"2.0.1+dfsg-1.1+deb8u1", rls:"DEB8"))) {
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
