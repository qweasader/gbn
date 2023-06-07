# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.879600");
  script_version("2021-08-24T03:01:09+0000");
  script_cve_id("CVE-2021-3482", "CVE-2021-29458", "CVE-2021-29457", "CVE-2021-29470", "CVE-2021-29473");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-24 03:01:09 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 18:55:00 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-15 03:09:13 +0000 (Sat, 15 May 2021)");
  script_name("Fedora: Security Advisory for exiv2 (FEDORA-2021-be94728b95)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-be94728b95");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2A5GMJEXQ5Q76JK6F6VKK5JYCLVFGKN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2'
  package(s) announced via the FEDORA-2021-be94728b95 advisory.");

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

  script_tag(name:"affected", value:"'exiv2' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.27.3~6.fc33", rls:"FC33"))) {
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