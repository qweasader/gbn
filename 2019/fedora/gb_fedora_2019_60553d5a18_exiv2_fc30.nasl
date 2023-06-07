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
  script_oid("1.3.6.1.4.1.25623.1.0.876643");
  script_version("2023-03-27T10:19:43+0000");
  script_cve_id("CVE-2019-13108", "CVE-2019-13109", "CVE-2019-13110", "CVE-2019-13111", "CVE-2019-13112", "CVE-2019-13113", "CVE-2019-13114");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-03-27 10:19:43 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 18:05:00 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-08-09 02:18:35 +0000 (Fri, 09 Aug 2019)");
  script_name("Fedora Update for exiv2 FEDORA-2019-60553d5a18");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-60553d5a18");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FGBT5OD2TF4AIXJUC56WOUJRHAZLZ4DC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2'
  package(s) announced via the FEDORA-2019-60553d5a18 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A command line utility to access image metadata, allowing one to:

  * print the Exif metadata of Jpeg images as summary info, interpreted values,
  or the plain data for each tag

  * print the Iptc metadata of Jpeg images

  * print the Jpeg comment of Jpeg images

  * set, add and delete Exif and Iptc metadata of Jpeg images

  * adjust the Exif timestamp (that&#39, s how it all started...)

  * rename Exif image files according to the Exif timestamp

  * extract, insert and delete Exif metadata (including thumbnails),
  Iptc metadata and Jpeg comments");

  script_tag(name:"affected", value:"'exiv2' package(s) on Fedora 30.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.27.2~1.fc30", rls:"FC30"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
