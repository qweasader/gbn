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
  script_oid("1.3.6.1.4.1.25623.1.0.878904");
  script_version("2021-02-12T05:36:42+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-12 05:36:42 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-09 04:02:23 +0000 (Tue, 09 Feb 2021)");
  script_name("Fedora: Security Advisory for pngcheck (FEDORA-2021-e24167b0e8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-e24167b0e8");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/R2VIWPUPEY7GOVITBPV4CEBDGPNGA54U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pngcheck'
  package(s) announced via the FEDORA-2021-e24167b0e8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pngcheck verifies the integrity of PNG, JNG and MNG files (by checking the
internal 32-bit CRCs [checksums] and decompressing the image data), it can
optionally dump almost all of the chunk-level information in the image in
human-readable form. For example, it can be used to print the basic statistics
about an image (dimensions, bit depth, etc.), to list the color and
transparency info in its palette (assuming it has one), or to extract the
embedded text annotations. This is a command-line program with batch
capabilities.

The current release supports all PNG, MNG and JNG chunks, including the newly
approved sTER stereo-layout chunk. It correctly reports errors in all but two
of the images in Chris Nokleberg&#39, s brokensuite-20061204.");

  script_tag(name:"affected", value:"'pngcheck' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"pngcheck", rpm:"pngcheck~2.4.0~7.fc32", rls:"FC32"))) {
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