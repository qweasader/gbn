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
  script_oid("1.3.6.1.4.1.25623.1.0.876168");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-7146", "CVE-2019-7148", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7664", "CVE-2019-7665", "CVE-2018-18520", "CVE-2018-18521", "CVE-2018-18310");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 19:53:00 +0000 (Tue, 30 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-05-07 02:37:26 +0000 (Tue, 07 May 2019)");
  script_name("Fedora Update for elfutils FEDORA-2019-44a9d99647");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-44a9d99647");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z6QQTO2CLXUBNNOX4DEZ5XXWJYV3SYVN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils'
  package(s) announced via the FEDORA-2019-44a9d99647 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Elfutils is a collection of utilities, including stack (to show
backtraces), nm (for listing symbols from object files), size
(for listing the section sizes of an object or archive file),
strip (for discarding symbols), readelf (to see the raw ELF file
structures), elflint (to check for well-formed ELF files) and
elfcompress (to compress or decompress ELF sections).");

  script_tag(name:"affected", value:"'elfutils' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.176~1.fc29", rls:"FC29"))) {
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
