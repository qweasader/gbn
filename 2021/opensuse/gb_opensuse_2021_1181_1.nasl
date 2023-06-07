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
  script_oid("1.3.6.1.4.1.25623.1.0.854097");
  script_version("2021-08-26T10:01:08+0000");
  script_cve_id("CVE-2019-25051");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-28 19:35:00 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-08-24 03:01:40 +0000 (Tue, 24 Aug 2021)");
  script_name("openSUSE: Security Advisory for aspell (openSUSE-SU-2021:1181-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1181-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KFDL4ZU73CCA7DXOG7N2VKN4DXLIO7WL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aspell'
  package(s) announced via the openSUSE-SU-2021:1181-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aspell fixes the following issues:

  - CVE-2019-25051: Fixed heap-buffer-overflow in acommon:ObjStack:dup_top
       (bsc#1188576).

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'aspell' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"aspell", rpm:"aspell~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspell-debuginfo", rpm:"aspell-debuginfo~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspell-debugsource", rpm:"aspell-debugsource~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspell-devel", rpm:"aspell-devel~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspell-ispell", rpm:"aspell-ispell~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspell-spell", rpm:"aspell-spell~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaspell15", rpm:"libaspell15~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaspell15-debuginfo", rpm:"libaspell15-debuginfo~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpspell15", rpm:"libpspell15~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpspell15-debuginfo", rpm:"libpspell15-debuginfo~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaspell15-32bit", rpm:"libaspell15-32bit~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaspell15-32bit-debuginfo", rpm:"libaspell15-32bit-debuginfo~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpspell15-32bit", rpm:"libpspell15-32bit~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpspell15-32bit-debuginfo", rpm:"libpspell15-32bit-debuginfo~0.60.8~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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