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
  script_oid("1.3.6.1.4.1.25623.1.0.878018");
  script_version("2021-07-16T11:00:51+0000");
  script_cve_id("CVE-2020-13625");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-17 20:15:00 +0000 (Thu, 17 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 03:42:37 +0000 (Thu, 02 Jul 2020)");
  script_name("Fedora: Security Advisory for php-PHPMailer (FEDORA-2020-0bbe6304e3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-0bbe6304e3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EFM3BZABL6RUHTVMXSC7OFMP4CKWMRPJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-PHPMailer'
  package(s) announced via the FEDORA-2020-0bbe6304e3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Full Featured Email Transfer Class for PHP. PHPMailer features:

  * Supports emails digitally signed with S/MIME encryption!

  * Supports emails with multiple TOs, CCs, BCCs and REPLY-TOs

  * Works on any platform.

  * Supports Text & HTML emails.

  * Embedded image support.

  * Multipart/alternative emails for mail clients that do not read
      HTML email.

  * Flexible debugging.

  * Custom mail headers.

  * Redundant SMTP servers.

  * Support for 8bit, base64, binary, and quoted-printable encoding.

  * Word wrap.

  * Multiple fs, string, and binary attachments (those from database,
      string, etc).

  * SMTP authentication.

  * Tested on multiple SMTP servers: Sendmail, qmail, Postfix, Gmail,
      Imail, Exchange, etc.

  * Good documentation, many examples included in download.

  * It&#39, s swift, small, and simple.");

  script_tag(name:"affected", value:"'php-PHPMailer' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"php-PHPMailer", rpm:"php-PHPMailer~5.2.28~2.fc31", rls:"FC31"))) {
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