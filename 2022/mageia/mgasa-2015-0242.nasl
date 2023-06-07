# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0242");
  script_cve_id("CVE-2015-1833");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0242");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0242.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16003");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/05/21/6");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/05/21/7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackrabbit' package(s) announced via the MGASA-2015-0242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated jackrabbit packages fix security vulnerability:

In Apache Jackrabbit before 2.4.6, When processing a WebDAV request body
containing XML, the XML parser can be instructed to read content from network
resources accessible to the host, identified by URI schemes such as 'http(s)'
or 'file'. Depending on the WebDAV request, this can not only be used to
trigger internal network requests, but might also be used to insert said
content into the request, potentially exposing it to the attacker and others
(for instance, by inserting said content in a WebDAV property value using a
PROPPATCH request). See also IETF RFC 4918, Section 20.6 (CVE-2015-1833).");

  script_tag(name:"affected", value:"'jackrabbit' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"jackrabbit", rpm:"jackrabbit~2.4.2~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackrabbit-webdav", rpm:"jackrabbit-webdav~2.4.2~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackrabbit-webdav-javadoc", rpm:"jackrabbit-webdav-javadoc~2.4.2~6.1.mga4", rls:"MAGEIA4"))) {
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
