# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704387");
  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_tag(name:"creation_date", value:"2019-02-08 23:00:00 +0000 (Fri, 08 Feb 2019)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 18:12:00 +0000 (Fri, 24 Mar 2023)");

  script_name("Debian: Security Advisory (DSA-4387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4387");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4387");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4387");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssh");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-4387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Harry Sintonen from F-Secure Corporation discovered multiple vulnerabilities in OpenSSH, an implementation of the SSH protocol suite. All the vulnerabilities are in found in the scp client implementing the SCP protocol.

CVE-2018-20685

Due to improper directory name validation, the scp client allows servers to modify permissions of the target directory by using empty or dot directory name.

CVE-2019-6109

Due to missing character encoding in the progress display, the object name can be used to manipulate the client output, for example to employ ANSI codes to hide additional files being transferred.

CVE-2019-6111

Due to scp client insufficient input validation in path names sent by server, a malicious server can do arbitrary file overwrites in target directory. If the recursive (-r) option is provided, the server can also manipulate subdirectories as well.

The check added in this version can lead to regression if the client and the server have differences in wildcard expansion rules. If the server is trusted for that purpose, the check can be disabled with a new -T option to the scp client.

For the stable distribution (stretch), these problems have been fixed in version 1:7.4p1-10+deb9u5.

We recommend that you upgrade your openssh packages.

For the detailed security status of openssh please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-ssh1", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:7.4p1-10+deb9u6", rls:"DEB9"))) {
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
