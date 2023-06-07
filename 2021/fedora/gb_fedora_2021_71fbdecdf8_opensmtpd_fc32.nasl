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
  script_oid("1.3.6.1.4.1.25623.1.0.878875");
  script_version("2022-04-28T03:04:10+0000");
  script_cve_id("CVE-2020-35679", "CVE-2020-35680");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-28 03:04:10 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-26 16:13:00 +0000 (Tue, 26 Apr 2022)");
  script_tag(name:"creation_date", value:"2021-02-01 04:02:04 +0000 (Mon, 01 Feb 2021)");
  script_name("Fedora: Security Advisory for opensmtpd (FEDORA-2021-71fbdecdf8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-71fbdecdf8");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TYAYXRV2DM5K4RU7RHCDZSA2UF6VCTRC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensmtpd'
  package(s) announced via the FEDORA-2021-71fbdecdf8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSMTPD is a FREE implementation of the server-side SMTP protocol as defined
by RFC 5321, with some additional standard extensions. It allows ordinary
machines to exchange e-mails with other systems speaking the SMTP protocol.
Started out of dissatisfaction with other implementations, OpenSMTPD nowadays
is a fairly complete SMTP implementation. OpenSMTPD is primarily developed
by Gilles Chehade, Eric Faurot and Charles Longeau, with contributions from
various OpenBSD hackers. OpenSMTPD is part of the OpenBSD Project.
The software is freely usable and re-usable by everyone under an ISC license.

This package uses standard 'alternatives' mechanism, you may call
'/usr/sbin/alternatives --set mta /usr/sbin/sendmail.opensmtpd'
if you want to switch to OpenSMTPD MTA immediately after install, and
'/usr/sbin/alternatives --set mta /usr/sbin/sendmail.sendmail' to revert
back to Sendmail as a default mail daemon.");

  script_tag(name:"affected", value:"'opensmtpd' package(s) on Fedora 32.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensmtpd", rpm:"opensmtpd~6.8.0p2~1.fc32", rls:"FC32"))) {
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