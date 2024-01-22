# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703164");
  script_cve_id("CVE-2015-2047");
  script_tag(name:"creation_date", value:"2015-02-20 23:00:00 +0000 (Fri, 20 Feb 2015)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3164-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3164-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3164-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3164");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-3164-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pierrick Caillon discovered that the authentication could be bypassed in the Typo 3 content management system. Please refer to the upstream advisory for additional information:

For the stable distribution (wheezy), this problem has been fixed in version 4.5.19+dfsg1-5+wheezy4.

The upcoming stable distribution (jessie) no longer includes Typo 3.

For the unstable distribution (sid), this problem has been fixed in version 4.5.40+dfsg1-1.

We recommend that you upgrade your typo3-src packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy4", rls:"DEB7"))) {
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
