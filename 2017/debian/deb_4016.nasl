# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704016");
  script_cve_id("CVE-2017-15227", "CVE-2017-15228", "CVE-2017-15721", "CVE-2017-15722", "CVE-2017-15723");
  script_tag(name:"creation_date", value:"2017-11-02 23:00:00 +0000 (Thu, 02 Nov 2017)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-14 16:19:00 +0000 (Thu, 14 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-4016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4016");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4016");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4016");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'irssi' package(s) announced via the DSA-4016 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Irssi, a terminal based IRC client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2017-10965

Brian geeknik Carpenter of Geeknik Labs discovered that Irssi does not properly handle receiving messages with invalid time stamps. A malicious IRC server can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

CVE-2017-10966

Brian geeknik Carpenter of Geeknik Labs discovered that Irssi is susceptible to a use-after-free flaw triggered while updating the internal nick list. A malicious IRC server can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

CVE-2017-15227

Joseph Bisch discovered that while waiting for the channel synchronisation, Irssi may incorrectly fail to remove destroyed channels from the query list, resulting in use after free conditions when updating the state later on. A malicious IRC server can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

CVE-2017-15228

Hanno Boeck reported that Irssi does not properly handle installing themes with unterminated colour formatting sequences, leading to a denial of service if a user is tricked into installing a specially crafted theme.

CVE-2017-15721

Joseph Bisch discovered that Irssi does not properly handle incorrectly formatted DCC CTCP messages. A remote attacker can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

CVE-2017-15722

Joseph Bisch discovered that Irssi does not properly verify Safe channel IDs. A malicious IRC server can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

CVE-2017-15723

Joseph Bisch reported that Irssi does not properly handle overlong nicks or targets resulting in a NULL pointer dereference when splitting the message and leading to a denial of service.

For the oldstable distribution (jessie), these problems have been fixed in version 0.8.17-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed in version 1.0.2-1+deb9u3. CVE-2017-10965 and CVE-2017-10966 were already fixed in an earlier point release.

We recommend that you upgrade your irssi packages.");

  script_tag(name:"affected", value:"'irssi' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"irssi-dbg", ver:"0.8.17-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irssi-dev", ver:"0.8.17-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irssi", ver:"0.8.17-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"irssi-dev", ver:"1.0.2-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irssi", ver:"1.0.2-1+deb9u3", rls:"DEB9"))) {
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