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
  script_oid("1.3.6.1.4.1.25623.1.0.818713");
  script_version("2021-10-08T06:07:28+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-08 06:07:28 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-02 01:22:49 +0000 (Sat, 02 Oct 2021)");
  script_name("Fedora: Security Advisory for proftpd (FEDORA-2021-7bb9676b2e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-7bb9676b2e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A3R4KCPSYMPFWQUO7EE4QXTDFHF3RQK6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd'
  package(s) announced via the FEDORA-2021-7bb9676b2e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
and ease of configuration. It features a very Apache-like configuration
syntax, and a highly customizable server infrastructure, including support for
multiple &#39, virtual&#39, FTP servers, anonymous FTP, and permission-based directory
visibility.

This package defaults to the standalone behavior of ProFTPD, but all the
needed scripts to have it run by systemd instead are included.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.7c~1.fc35", rls:"FC35"))) {
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