# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.293");
  script_cve_id("CVE-2015-3187");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-293-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-293-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DLA-293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"C. Michael Pilato, from CollabNet, reported an issue in the version control system Subversion.

CVE-2015-3187

Subversion servers revealed some sensible paths hidden by path-based authorization. Remote authenticated users were allowed to obtain path information by reading the history of a node that has been moved from a hidden path. The vulnerability only revealed the path, though it didn't reveal its content.

For Debian 6 Squeeze, this issue has been fixed in subversion 1.6.12dfsg-7+deb6u3. We recommend to upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"subversion", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.12dfsg-7+deb6u3", rls:"DEB6"))) {
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
