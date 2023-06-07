# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893257");
  script_cve_id("CVE-2022-45939");
  script_tag(name:"creation_date", value:"2023-01-01 02:00:47 +0000 (Sun, 01 Jan 2023)");
  script_version("2023-03-09T10:20:44+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:44 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 19:48:00 +0000 (Thu, 01 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3257");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3257");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'emacs' package(s) announced via the DLA-3257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in Emacs where where attackers could have executed arbitrary commands via shell metacharacters in the name of a source-code file.

This was because lib-src/etags.c used the system(3) library function when calling the (external) ctags(1) binary.

CVE-2022-45939

GNU Emacs through 28.2 allows attackers to execute commands via shell metacharacters in the name of a source-code file, because lib-src/etags.c uses the system C library function in its implementation of the ctags program. For example, a victim may use the 'ctags *' command (suggested in the ctags documentation) in a situation where the current working directory has contents that depend on untrusted input.

For Debian 10 Buster, this problem has been fixed in version 1:26.1+1-3.2+deb10u3.

We recommend that you upgrade your emacs packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'emacs' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-gtk", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-lucid", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-nox", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs21-nox", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs21", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs22-gtk", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs22-nox", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs22", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs23-lucid", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs23-nox", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs23", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs24-lucid", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs24-nox", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs24", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs25-lucid", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs25-nox", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs25", ver:"1:26.1+1-3.2+deb10u3", rls:"DEB10"))) {
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
