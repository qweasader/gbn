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
  script_oid("1.3.6.1.4.1.25623.1.0.877460");
  script_version("2021-07-19T11:00:51+0000");
  script_cve_id("CVE-2020-1930", "CVE-2020-1931");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-02 04:15:00 +0000 (Sun, 02 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-12 04:06:18 +0000 (Wed, 12 Feb 2020)");
  script_name("Fedora: Security Advisory for spamassassin (FEDORA-2020-bd20036cdc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2020-bd20036cdc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VOVVKFP2G2AF5GHAB4WMHOEX76A3H6CE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spamassassin'
  package(s) announced via the FEDORA-2020-bd20036cdc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SpamAssassin provides you with a way to reduce if not completely eliminate
Unsolicited Commercial Email (SPAM) from your incoming email.  It can
be invoked by a MDA such as sendmail or postfix, or can be called from
a procmail script, .forward file, etc.  It uses a genetic-algorithm
evolved scoring system to identify messages which look spammy, then
adds headers to the message so they can be filtered by the user&#39, s mail
reading software.  This distribution includes the spamd/spamc components
which create a server that considerably speeds processing of mail.

To enable spamassassin, if you are receiving mail locally, simply add
this line to your ~/.procmailrc:
INCLUDERC=/etc/mail/spamassassin/spamassassin-default.rc

To filter spam for all users, add that line to /etc/procmailrc
(creating if necessary).");

  script_tag(name:"affected", value:"'spamassassin' package(s) on Fedora 30.");

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

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.4~1.fc30", rls:"FC30"))) {
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