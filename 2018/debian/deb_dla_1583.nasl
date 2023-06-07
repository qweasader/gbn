# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891583");
  script_cve_id("CVE-2015-5203", "CVE-2015-5221", "CVE-2016-8690", "CVE-2017-13748", "CVE-2017-14132");
  script_tag(name:"creation_date", value:"2018-11-20 23:00:00 +0000 (Tue, 20 Nov 2018)");
  script_version("2023-03-09T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:43 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-05 14:53:00 +0000 (Fri, 05 Feb 2021)");

  script_name("Debian: Security Advisory (DLA-1583)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1583");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1583");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jasper' package(s) announced via the DLA-1583 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in the JasPer JPEG-2000 library.

CVE-2015-5203

Gustavo Grieco discovered an integer overflow vulnerability that allows remote attackers to cause a denial of service or may have other unspecified impact via a crafted JPEG 2000 image file.

CVE-2015-5221

Josselin Feist found a double-free vulnerability that allows remote attackers to cause a denial-of-service (application crash) by processing a malformed image file.

CVE-2016-8690

Gustavo Grieco discovered a NULL pointer dereference vulnerability that can cause a denial-of-service via a crafted BMP image file. The update also includes the fixes for the related issues CVE-2016-8884 and CVE-2016-8885 which complete the patch for CVE-2016-8690.

CVE-2017-13748

It was discovered that jasper does not properly release memory used to store image tile data when image decoding fails which may lead to a denial-of-service.

CVE-2017-14132

A heap-based buffer over-read was found related to the jas_image_ishomosamp function that could be triggered via a crafted image file and may cause a denial-of-service (application crash) or have other unspecified impact.

For Debian 8 Jessie, these problems have been fixed in version 1.900.1-debian1-2.4+deb8u4.

We recommend that you upgrade your jasper packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jasper' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-debian1-2.4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-debian1-2.4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-debian1-2.4+deb8u4", rls:"DEB8"))) {
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
