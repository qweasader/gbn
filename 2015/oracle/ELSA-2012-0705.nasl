# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.123911");
  script_cve_id("CVE-2012-1149", "CVE-2012-2334");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:11 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T07:50:33+0000");
  script_tag(name:"last_modification", value:"2022-04-05 07:50:33 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0705)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0705");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0705.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org' package(s) announced via the ELSA-2012-0705 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:3.2.1-19.6.0.1.el6_2.7]
- Replaced RedHat colors with Oracle colors, OOO_VENDOR with Oracle Corp.,
 and the filename redhat.soc with oracle.soc in specfile

[1:3.2.1-19.6.7]
- Resolves: CVE-2012-2334 Integer overflow leading to buffer overflow by
 processing invalid Escher graphics records length in the Powerpoint
 documents

[1:3.2.1-19.6.6]
- Resolves: CVE-2012-1149 Integer overflows, leading to heap-buffer
 overflows in JPEG, PNG and BMP reader implementations");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"autocorr-af", rpm:"autocorr-af~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-bg", rpm:"autocorr-bg~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-cs", rpm:"autocorr-cs~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-da", rpm:"autocorr-da~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-de", rpm:"autocorr-de~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-en", rpm:"autocorr-en~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-es", rpm:"autocorr-es~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-eu", rpm:"autocorr-eu~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fa", rpm:"autocorr-fa~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fi", rpm:"autocorr-fi~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fr", rpm:"autocorr-fr~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ga", rpm:"autocorr-ga~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-hu", rpm:"autocorr-hu~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-it", rpm:"autocorr-it~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ja", rpm:"autocorr-ja~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ko", rpm:"autocorr-ko~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-lb", rpm:"autocorr-lb~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-lt", rpm:"autocorr-lt~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-mn", rpm:"autocorr-mn~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-nl", rpm:"autocorr-nl~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-pl", rpm:"autocorr-pl~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-pt", rpm:"autocorr-pt~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ru", rpm:"autocorr-ru~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sk", rpm:"autocorr-sk~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sl", rpm:"autocorr-sl~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sv", rpm:"autocorr-sv~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-tr", rpm:"autocorr-tr~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-vi", rpm:"autocorr-vi~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-zh", rpm:"autocorr-zh~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-base", rpm:"broffice.org-base~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-brand", rpm:"broffice.org-brand~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-calc", rpm:"broffice.org-calc~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-draw", rpm:"broffice.org-draw~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-impress", rpm:"broffice.org-impress~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-math", rpm:"broffice.org-math~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broffice.org-writer", rpm:"broffice.org-writer~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-base-core", rpm:"openoffice.org-base-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-brand", rpm:"openoffice.org-brand~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-bsh", rpm:"openoffice.org-bsh~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-calc-core", rpm:"openoffice.org-calc-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-draw-core", rpm:"openoffice.org-draw-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-emailmerge", rpm:"openoffice.org-emailmerge~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-graphicfilter", rpm:"openoffice.org-graphicfilter~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-headless", rpm:"openoffice.org-headless~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-impress-core", rpm:"openoffice.org-impress-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-javafilter", rpm:"openoffice.org-javafilter~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-af_ZA", rpm:"openoffice.org-langpack-af_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ar", rpm:"openoffice.org-langpack-ar~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-as_IN", rpm:"openoffice.org-langpack-as_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-bg_BG", rpm:"openoffice.org-langpack-bg_BG~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-bn", rpm:"openoffice.org-langpack-bn~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ca_ES", rpm:"openoffice.org-langpack-ca_ES~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-cs_CZ", rpm:"openoffice.org-langpack-cs_CZ~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-cy_GB", rpm:"openoffice.org-langpack-cy_GB~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-da_DK", rpm:"openoffice.org-langpack-da_DK~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-de", rpm:"openoffice.org-langpack-de~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-dz", rpm:"openoffice.org-langpack-dz~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-el_GR", rpm:"openoffice.org-langpack-el_GR~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-en", rpm:"openoffice.org-langpack-en~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-es", rpm:"openoffice.org-langpack-es~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-et_EE", rpm:"openoffice.org-langpack-et_EE~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-eu_ES", rpm:"openoffice.org-langpack-eu_ES~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-fi_FI", rpm:"openoffice.org-langpack-fi_FI~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-fr", rpm:"openoffice.org-langpack-fr~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ga_IE", rpm:"openoffice.org-langpack-ga_IE~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-gl_ES", rpm:"openoffice.org-langpack-gl_ES~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-gu_IN", rpm:"openoffice.org-langpack-gu_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-he_IL", rpm:"openoffice.org-langpack-he_IL~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-hi_IN", rpm:"openoffice.org-langpack-hi_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-hr_HR", rpm:"openoffice.org-langpack-hr_HR~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-hu_HU", rpm:"openoffice.org-langpack-hu_HU~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-it", rpm:"openoffice.org-langpack-it~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ja_JP", rpm:"openoffice.org-langpack-ja_JP~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-kn_IN", rpm:"openoffice.org-langpack-kn_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ko_KR", rpm:"openoffice.org-langpack-ko_KR~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-lt_LT", rpm:"openoffice.org-langpack-lt_LT~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-mai_IN", rpm:"openoffice.org-langpack-mai_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ml_IN", rpm:"openoffice.org-langpack-ml_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-mr_IN", rpm:"openoffice.org-langpack-mr_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ms_MY", rpm:"openoffice.org-langpack-ms_MY~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-nb_NO", rpm:"openoffice.org-langpack-nb_NO~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-nl", rpm:"openoffice.org-langpack-nl~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-nn_NO", rpm:"openoffice.org-langpack-nn_NO~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-nr_ZA", rpm:"openoffice.org-langpack-nr_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-nso_ZA", rpm:"openoffice.org-langpack-nso_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-or_IN", rpm:"openoffice.org-langpack-or_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-pa", rpm:"openoffice.org-langpack-pa~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-pl_PL", rpm:"openoffice.org-langpack-pl_PL~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-pt_BR", rpm:"openoffice.org-langpack-pt_BR~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-pt_PT", rpm:"openoffice.org-langpack-pt_PT~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ro", rpm:"openoffice.org-langpack-ro~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ru", rpm:"openoffice.org-langpack-ru~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-sk_SK", rpm:"openoffice.org-langpack-sk_SK~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-sl_SI", rpm:"openoffice.org-langpack-sl_SI~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-sr", rpm:"openoffice.org-langpack-sr~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ss_ZA", rpm:"openoffice.org-langpack-ss_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-st_ZA", rpm:"openoffice.org-langpack-st_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-sv", rpm:"openoffice.org-langpack-sv~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ta_IN", rpm:"openoffice.org-langpack-ta_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-te_IN", rpm:"openoffice.org-langpack-te_IN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-th_TH", rpm:"openoffice.org-langpack-th_TH~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-tn_ZA", rpm:"openoffice.org-langpack-tn_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-tr_TR", rpm:"openoffice.org-langpack-tr_TR~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ts_ZA", rpm:"openoffice.org-langpack-ts_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-uk", rpm:"openoffice.org-langpack-uk~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ur", rpm:"openoffice.org-langpack-ur~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-ve_ZA", rpm:"openoffice.org-langpack-ve_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-xh_ZA", rpm:"openoffice.org-langpack-xh_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-zh_CN", rpm:"openoffice.org-langpack-zh_CN~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-zh_TW", rpm:"openoffice.org-langpack-zh_TW~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-langpack-zu_ZA", rpm:"openoffice.org-langpack-zu_ZA~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-math-core", rpm:"openoffice.org-math-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-ogltrans", rpm:"openoffice.org-ogltrans~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-opensymbol-fonts", rpm:"openoffice.org-opensymbol-fonts~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-pdfimport", rpm:"openoffice.org-pdfimport~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-presentation-minimizer", rpm:"openoffice.org-presentation-minimizer~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-presenter-screen", rpm:"openoffice.org-presenter-screen~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-report-builder", rpm:"openoffice.org-report-builder~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-rhino", rpm:"openoffice.org-rhino~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-sdk", rpm:"openoffice.org-sdk~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-sdk-doc", rpm:"openoffice.org-sdk-doc~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-testtools", rpm:"openoffice.org-testtools~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-ure", rpm:"openoffice.org-ure~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-wiki-publisher", rpm:"openoffice.org-wiki-publisher~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-writer-core", rpm:"openoffice.org-writer-core~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openoffice.org-xsltfilter", rpm:"openoffice.org-xsltfilter~3.2.1~19.6.0.1.el6_2.7", rls:"OracleLinux6"))) {
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
