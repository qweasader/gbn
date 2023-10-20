# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54354");
  script_cve_id("CVE-2005-1921");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-746)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-746");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-746");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-746");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-746 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability had been identified in the xmlrpc library included with phpgroupware, a web-based application including email, calendar and other groupware functionality. This vulnerability could lead to the execution of arbitrary commands on the server running phpgroupware.

The security team is continuing to investigate the version of phpgroupware included with the old stable distribution (woody). At this time we recommend disabling phpgroupware or upgrading to the current stable distribution (sarge).

For the current stable distribution (sarge) this problem has been fixed in version 0.9.16.005-3.sarge0.

For the unstable distribution (sid) this problem has been fixed in version 0.9.16.006-1.

We recommend that you upgrade your phpgroupware package.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-etemplate", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-felamimail", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-folders", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-fudforum", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpbrain", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpgwapi", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-qmailldap", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-sitemgr", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-wiki", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.16.005-3.sarge0", rls:"DEB3.1"))) {
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
