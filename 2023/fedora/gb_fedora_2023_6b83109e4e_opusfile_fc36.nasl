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
  script_oid("1.3.6.1.4.1.25623.1.0.827097");
  script_version("2023-02-15T10:19:49+0000");
  script_cve_id("CVE-2022-47021");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-15 10:19:49 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-10 02:01:58 +0000 (Fri, 10 Feb 2023)");
  script_name("Fedora: Security Advisory for opusfile (FEDORA-2023-6b83109e4e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6b83109e4e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MYPAQANM2ZNPXRBFOS5NFXNJ7O4Q3OBD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opusfile'
  package(s) announced via the FEDORA-2023-6b83109e4e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libopusfile provides a high-level API for decoding and seeking
within .opus files. It includes:

  * Support for all files with at least one Opus stream (including
multichannel files or Ogg files where Opus is muxed with something else).

  * Full support, including seeking, for chained files.

  * A simple stereo downmixing API (allowing chained files to be
decoded with a single output format, even if the channel count changes).

  * Support for reading from a file, memory buffer, or over HTTP(S)
(including seeking).

  * Support for both random access and streaming data sources.");

  script_tag(name:"affected", value:"'opusfile' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"opusfile", rpm:"opusfile~0.12~9.fc36", rls:"FC36"))) {
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