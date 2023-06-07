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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1076.1");
  script_cve_id("CVE-2017-9432", "CVE-2017-9433", "CVE-2018-1055", "CVE-2018-6871");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1076-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181076-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice' package(s) announced via the SUSE-SU-2018:1076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibreOffice was updated to version 6.0.3.
Following new features were added:
- The Notebookbar, although still an experimental feature, has been
 enriched with two new variants: Grouped Bar Full for Writer, Calc and
 Impress, and Tabbed Compact for Writer. The Special Characters dialog
 has been reworked, with the addition of lists for Recent and Favorite
 characters, along with a Search field. The Customize dialog has also
 been redesigned, and is now more modern and intuitive.
- In Writer, a Form menu has been added, making it easier to access one
 of the most powerful AC/AEURA' and often unknown AC/AEURA' LibreOffice features: the
 ability to design forms, and create standards-compliant PDF forms. The
 Find toolbar has been enhanced with a drop-down list of search types,
 to speed up navigation. A new default table style has been added,
 together with a new collection of table styles to reflect evolving
 visual trends.
- The Mail Merge function has been improved, and it is now possible to use
 either a Writer document or an XLSX file as data source.
- In Calc, ODF 1.2-compliant functions SEARCHB, FINDB and REPLACEB have
 been added, to improve support for the ISO standard format. Also, a cell
 range selection or a selected group of shapes (images) can be now
 exported in PNG or JPG format.
- In Impress, the default slide size has been switched to 16:9, to support
 the most recent form factors of screens and projectors. As a
 consequence, 10 new Impress templates have been added, and a couple of
 old templates have been updated.
Changes in components:
- The old WikiHelp has been replaced by the new Help Online system, with
 attractive web pages that can also be displayed on mobile devices. In
 general, LibreOffice Help has been updated both in terms of contents and
 code, with other improvements due all along the life of the LibreOffice
 6 family.
- User dictionaries now allow automatic affixation or compounding. This is
 a general spell checking improvement in LibreOffice which can speed up
 work for Writer users. Instead of manually handling several forms of a
 new word in a language with rich morphology or compounding, the Hunspell
 spell checker can automatically recognize a new word with affixes or
 compounds, based on a AC/AEURAoeGrammar ByAC/AEURA model.
Security features and changes:
- OpenPGP keys can be used to sign ODF documents on all desktop operating
 systems, with experimental support for OpenPGP-based encryption. To
 enable this feature, users will have to install the specific GPG
 software for their operating systems.
- Document classification has also been improved, and allows multiple
 policies (which are now exported to OOXML files). In Writer, marking and
 signing are now supported at paragraph level.
Interoperability changes:
- OOXML interoperability has been improved in several areas: import of
 SmartArt and import/export of ActiveX controls, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'LibreOffice' package(s) on SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"boost-license1_54_0", rpm:"boost-license1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_54_0", rpm:"libboost_atomic1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_54_0-debuginfo", rpm:"libboost_atomic1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_54_0", rpm:"libboost_date_time1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_54_0-debuginfo", rpm:"libboost_date_time1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_54_0", rpm:"libboost_iostreams1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_54_0-debuginfo", rpm:"libboost_iostreams1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_54_0", rpm:"libboost_program_options1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_54_0-debuginfo", rpm:"libboost_program_options1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_54_0", rpm:"libboost_random1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_54_0-debuginfo", rpm:"libboost_random1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_54_0", rpm:"libboost_regex1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_54_0-debuginfo", rpm:"libboost_regex1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_54_0", rpm:"libboost_signals1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_54_0-debuginfo", rpm:"libboost_signals1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_54_0", rpm:"libboost_system1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_54_0-debuginfo", rpm:"libboost_system1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_54_0", rpm:"libboost_thread1_54_0~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_54_0-debuginfo", rpm:"libboost_thread1_54_0-debuginfo~1.54.0~26.3.1", rls:"SLES12.0SP3"))) {
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
