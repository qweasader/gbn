# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883278");
  script_version("2021-07-06T02:00:40+0000");
  script_cve_id("CVE-2020-12100", "CVE-2020-12673", "CVE-2020-12674");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-06 23:15:00 +0000 (Wed, 06 Jan 2021)");
  script_tag(name:"creation_date", value:"2020-09-15 03:00:33 +0000 (Tue, 15 Sep 2020)");
  script_name("CentOS: Security Advisory for dovecot (CESA-2020:3617)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:3617");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-September/035809.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot'
  package(s) announced via the CESA-2020:3617 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dovecot is an IMAP server for Linux and other UNIX-like systems, written
primarily with security in mind. It also contains a small POP3 server, and
supports e-mail in either the maildir or mbox format. The SQL drivers and
authentication plug-ins are provided as subpackages.

Security Fix(es):

  * dovecot: Resource exhaustion via deeply nested MIME parts
(CVE-2020-12100)

  * dovecot: Out of bound reads in dovecot NTLM implementation
(CVE-2020-12673)

  * dovecot: Crash due to assert in RPA implementation (CVE-2020-12674)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'dovecot' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.2.36~6.el7_8.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~2.2.36~6.el7_8.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~2.2.36~6.el7_8.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~2.2.36~6.el7_8.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.2.36~6.el7_8.1", rls:"CentOS7"))) {
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