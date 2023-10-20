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
  script_oid("1.3.6.1.4.1.25623.1.0.854939");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-2625");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 19:09:00 +0000 (Fri, 19 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-09-02 01:03:04 +0000 (Fri, 02 Sep 2022)");
  script_name("openSUSE: Security Advisory for postgresql13 (SUSE-SU-2022:2987-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2987-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GQNFBGRYCEBZFF2PAFIPT243O6XN6OFE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql13'
  package(s) announced via the SUSE-SU-2022:2987-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql13 fixes the following issues:

  - Update to 13.8:

  - CVE-2022-2625: Fixed an issue where extension scripts would replace
       objects not belonging to that extension (bsc#1202368).");

  script_tag(name:"affected", value:"'postgresql13' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql13", rpm:"postgresql13~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-contrib", rpm:"postgresql13-contrib~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-contrib-debuginfo", rpm:"postgresql13-contrib-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-debuginfo", rpm:"postgresql13-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-debugsource", rpm:"postgresql13-debugsource~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-devel", rpm:"postgresql13-devel~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-devel-debuginfo", rpm:"postgresql13-devel-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit", rpm:"postgresql13-llvmjit~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit-debuginfo", rpm:"postgresql13-llvmjit-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit-devel", rpm:"postgresql13-llvmjit-devel~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plperl", rpm:"postgresql13-plperl~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plperl-debuginfo", rpm:"postgresql13-plperl-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plpython", rpm:"postgresql13-plpython~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plpython-debuginfo", rpm:"postgresql13-plpython-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-pltcl", rpm:"postgresql13-pltcl~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-pltcl-debuginfo", rpm:"postgresql13-pltcl-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server", rpm:"postgresql13-server~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-debuginfo", rpm:"postgresql13-server-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-devel", rpm:"postgresql13-server-devel~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-devel-debuginfo", rpm:"postgresql13-server-devel-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-test", rpm:"postgresql13-test~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-docs", rpm:"postgresql13-docs~13.8~150200.5.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql13", rpm:"postgresql13~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-contrib", rpm:"postgresql13-contrib~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-contrib-debuginfo", rpm:"postgresql13-contrib-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-debuginfo", rpm:"postgresql13-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-debugsource", rpm:"postgresql13-debugsource~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-devel", rpm:"postgresql13-devel~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-devel-debuginfo", rpm:"postgresql13-devel-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit", rpm:"postgresql13-llvmjit~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit-debuginfo", rpm:"postgresql13-llvmjit-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plperl", rpm:"postgresql13-plperl~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plperl-debuginfo", rpm:"postgresql13-plperl-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plpython", rpm:"postgresql13-plpython~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plpython-debuginfo", rpm:"postgresql13-plpython-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-pltcl", rpm:"postgresql13-pltcl~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-pltcl-debuginfo", rpm:"postgresql13-pltcl-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server", rpm:"postgresql13-server~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-debuginfo", rpm:"postgresql13-server-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-devel", rpm:"postgresql13-server-devel~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-devel-debuginfo", rpm:"postgresql13-server-devel-debuginfo~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-test", rpm:"postgresql13-test~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-docs", rpm:"postgresql13-docs~13.8~150200.5.31.1", rls:"openSUSELeap15.3"))) {
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