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
  script_oid("1.3.6.1.4.1.25623.1.0.879034");
  script_version("2021-08-23T14:00:58+0000");
  script_cve_id("CVE-2021-3407");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-03-06 04:08:41 +0000 (Sat, 06 Mar 2021)");
  script_name("Fedora: Security Advisory for mupdf (FEDORA-2021-572bb0f886)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-572bb0f886");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IPNOEYEHMEJ6JCKVFPPQQSH2QFXYU2BZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mupdf'
  package(s) announced via the FEDORA-2021-572bb0f886 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MuPDF is a lightweight PDF viewer and toolkit written in portable C.
The renderer in MuPDF is tailored for high quality anti-aliased
graphics.  MuPDF renders text with metrics and spacing accurate to
within fractions of a pixel for the highest fidelity in reproducing
the look of a printed page on screen.
MuPDF has a small footprint.  A binary that includes the standard
Roman fonts is only one megabyte.  A build with full CJK support
(including an Asian font) is approximately five megabytes.
MuPDF has support for all non-interactive PDF 1.7 features, and the
toolkit provides a simple API for accessing the internal structures of
the PDF document.  Example code for navigating interactive links and
bookmarks, encrypting PDF files, extracting fonts, images, and
searchable text, and rendering pages to image files is provided.");

  script_tag(name:"affected", value:"'mupdf' package(s) on Fedora 33.");

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

  if(!isnull(res = isrpmvuln(pkg:"mupdf", rpm:"mupdf~1.18.0~5.fc33", rls:"FC33"))) {
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