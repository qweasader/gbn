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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0163");
  script_cve_id("CVE-2022-1520", "CVE-2022-29909", "CVE-2022-29911", "CVE-2022-29912", "CVE-2022-29913", "CVE-2022-29914", "CVE-2022-29916", "CVE-2022-29917");
  script_tag(name:"creation_date", value:"2022-05-09 04:28:10 +0000 (Mon, 09 May 2022)");
  script_version("2023-01-02T10:12:16+0000");
  script_tag(name:"last_modification", value:"2023-01-02 10:12:16 +0000 (Mon, 02 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 22:12:00 +0000 (Fri, 30 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0163");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0163.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30374");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-18/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/91.9.0/releasenotes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird, thunderbird-l10n' package(s) announced via the MGASA-2022-0163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect security status shown after viewing an attached email.
(CVE-2022-1520)
Fullscreen notification bypass using popups. (CVE-2022-29914)
Bypassing permission prompt in nested browsing contexts. (CVE-2022-29909)
Leaking browser history with CSS variables. (CVE-2022-29916)
iframe sandbox bypass. (CVE-2022-29911)
Reader mode bypassed SameSite cookies. (CVE-2022-29912)
Speech Synthesis feature not properly disabled. (CVE-2022-29913)
Memory safety bugs fixed in Thunderbird 91.9. (CVE-2022-29917)");

  script_tag(name:"affected", value:"'thunderbird, thunderbird-l10n' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-af", rpm:"thunderbird-af~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cy", rpm:"thunderbird-cy~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-dsb", rpm:"thunderbird-dsb~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_CA", rpm:"thunderbird-en_CA~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_US", rpm:"thunderbird-en_US~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy_NL", rpm:"thunderbird-fy_NL~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga_IE", rpm:"thunderbird-ga_IE~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hr", rpm:"thunderbird-hr~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hsb", rpm:"thunderbird-hsb~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hy_AM", rpm:"thunderbird-hy_AM~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ka", rpm:"thunderbird-ka~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-kab", rpm:"thunderbird-kab~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-kk", rpm:"thunderbird-kk~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lv", rpm:"thunderbird-lv~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ms", rpm:"thunderbird-ms~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pa_IN", rpm:"thunderbird-pa_IN~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sr", rpm:"thunderbird-sr~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-th", rpm:"thunderbird-th~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uz", rpm:"thunderbird-uz~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~91.9.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~91.9.0~1.mga8", rls:"MAGEIA8"))) {
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
