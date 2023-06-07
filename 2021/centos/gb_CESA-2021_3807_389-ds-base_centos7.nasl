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
  script_oid("1.3.6.1.4.1.25623.1.0.883389");
  script_version("2022-11-30T10:12:07+0000");
  script_cve_id("CVE-2021-3652");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-11-30 10:12:07 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 19:54:00 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"creation_date", value:"2021-11-18 02:02:06 +0000 (Thu, 18 Nov 2021)");
  script_name("CentOS: Security Advisory for 389-ds-base (CESA-2021:3807)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:3807");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-November/048372.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the CESA-2021:3807 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3 (LDAPv3) compliant server. The
base packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

Security Fix(es):

  * 389-ds-base: CRYPT password hash with asterisk allows any bind attempt to
succeed (CVE-2021-3652)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * A plugin can create an index. Even if the index can be used immediately
(for
searches) the index remains offline until further reindex (BZ#2005399)

  * In some rare case, a replication connection may be treated as a regular
connection and ACIs evaluated even if they should not. (BZ#2005434)

  * A regular connection can be erroneously flagged replication connection
(BZ#2005435)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.10.2~13.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.10.2~13.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.10.2~13.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.10.2~13.el7_9", rls:"CentOS7"))) {
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