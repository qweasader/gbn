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
  script_oid("1.3.6.1.4.1.25623.1.0.854185");
  script_version("2022-01-12T03:03:19+0000");
  script_cve_id("CVE-2021-3622");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-01-12 03:03:19 +0000 (Wed, 12 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-10 13:37:00 +0000 (Mon, 10 Jan 2022)");
  script_tag(name:"creation_date", value:"2021-09-24 01:20:56 +0000 (Fri, 24 Sep 2021)");
  script_name("openSUSE: Security Advisory for hivex (openSUSE-SU-2021:3201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3201-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5FC5F3EO3ROUN3SV32U3TNFWTKZ6B6TA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hivex'
  package(s) announced via the openSUSE-SU-2021:3201-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hivex fixes the following issues:

  - CVE-2021-3622: Fixed stack overflow due to recursive call of
       _get_children() (bsc#1189060).");

  script_tag(name:"affected", value:"'hivex' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"hivex", rpm:"hivex~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-debuginfo", rpm:"hivex-debuginfo~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-debugsource", rpm:"hivex-debugsource~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-devel", rpm:"hivex-devel~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhivex0", rpm:"libhivex0~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhivex0-debuginfo", rpm:"libhivex0-debuginfo~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex", rpm:"ocaml-hivex~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-debuginfo", rpm:"ocaml-hivex-debuginfo~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-devel", rpm:"ocaml-hivex-devel~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Win-Hivex", rpm:"perl-Win-Hivex~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Win-Hivex-debuginfo", rpm:"perl-Win-Hivex-debuginfo~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-hivex", rpm:"python-hivex~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-hivex-debuginfo", rpm:"python-hivex-debuginfo~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-lang", rpm:"hivex-lang~1.3.14~5.6.1", rls:"openSUSELeap15.3"))) {
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