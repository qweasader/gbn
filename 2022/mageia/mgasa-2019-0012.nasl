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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0012");
  script_cve_id("CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 16:29:00 +0000 (Mon, 03 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0012");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0012.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24074");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3845-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2019-0012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings. A malicious server could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code (CVE-2018-8784, CVE-2018-8785).

Eyal Itkin discovered FreeRDP incorrectly handled bitmaps. A malicious
server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code (CVE-2018-8786,
CVE-2018-8787).

Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings. A malicious server could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code (CVE-2018-8788).

Eyal Itkin discovered FreeRDP incorrectly handled NTLM authentication. A
malicious server could use this issue to cause FreeRDP to crash,
resulting in a denial of service, or possibly execute arbitrary code
(CVE-2018-8789).");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~0.rc4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.0.0~0.rc4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.0.0~0.rc4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.0.0~0.rc4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.0.0~0.rc4.1.mga6", rls:"MAGEIA6"))) {
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
