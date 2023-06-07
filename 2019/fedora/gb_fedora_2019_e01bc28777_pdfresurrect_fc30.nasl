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
  script_oid("1.3.6.1.4.1.25623.1.0.876758");
  script_version("2023-03-02T10:19:53+0000");
  script_cve_id("CVE-2019-14267", "CVE-2019-14934");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 15:19:00 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-09-07 02:23:52 +0000 (Sat, 07 Sep 2019)");
  script_name("Fedora Update for pdfresurrect FEDORA-2019-e01bc28777");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-e01bc28777");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LXN6W5QTNQJ2LFDCQWKYSMMZ3NPUWP3U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdfresurrect'
  package(s) announced via the FEDORA-2019-e01bc28777 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PDFResurrect is a tool aimed at analyzing PDF documents. The PDF format
allows for previous document changes to be retained in a more recent
version of the document, thereby creating a running history of changes
for the document. This tool attempts to extract all previous versions
while also producing a summary of changes between versions. This tool
can also 'scrub' or write data over the original instances of PDF objects
that have been modified or deleted, in an effort to disguise information
from previous versions that might not be intended for anyone else to read.");

  script_tag(name:"affected", value:"'pdfresurrect' package(s) on Fedora 30.");

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

  if(!isnull(res = isrpmvuln(pkg:"pdfresurrect", rpm:"pdfresurrect~0.18~1.fc30", rls:"FC30"))) {
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
