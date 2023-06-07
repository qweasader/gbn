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
  script_oid("1.3.6.1.4.1.25623.1.0.854471");
  script_version("2022-02-22T09:18:02+0000");
  script_cve_id("CVE-2021-3999", "CVE-2022-23218", "CVE-2022-23219");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 09:18:02 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 03:46:00 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 08:16:57 +0000 (Tue, 08 Feb 2022)");
  script_name("openSUSE: Security Advisory for glibc (openSUSE-SU-2022:0330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0330-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WUNMTSOEM6LU65NFICFVIHBARFG7LVO7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the openSUSE-SU-2022:0330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glibc fixes the following issues:

  - CVE-2021-3999: Fixed incorrect errno in getcwd (bsc#1194640)

  - CVE-2022-23219: Fixed buffer overflow in sunrpc clnt_create for 'unix'
       (bsc#1194768)

  - CVE-2022-23218: Fixed buffer overflow in sunrpc svcunix_create
       (bsc#1194770)
  Features added:

  - IBM Power 10 string operation improvements (bsc#1194785, jsc#SLE-18195)");

  script_tag(name:"affected", value:"'glibc' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debugsource", rpm:"glibc-debugsource~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-debuginfo", rpm:"glibc-devel-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static", rpm:"glibc-devel-static~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra", rpm:"glibc-extra~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra-debuginfo", rpm:"glibc-extra-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base", rpm:"glibc-locale-base~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-debuginfo", rpm:"glibc-locale-base-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo", rpm:"glibc-utils-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-src-debugsource", rpm:"glibc-utils-src-debugsource~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd-debuginfo", rpm:"nscd-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-lang", rpm:"glibc-lang~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit-debuginfo", rpm:"glibc-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit-debuginfo", rpm:"glibc-devel-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static-32bit", rpm:"glibc-devel-static-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-32bit", rpm:"glibc-locale-base-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-32bit-debuginfo", rpm:"glibc-locale-base-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit", rpm:"glibc-utils-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit-debuginfo", rpm:"glibc-utils-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debugsource", rpm:"glibc-debugsource~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-debuginfo", rpm:"glibc-devel-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static", rpm:"glibc-devel-static~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra", rpm:"glibc-extra~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra-debuginfo", rpm:"glibc-extra-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base", rpm:"glibc-locale-base~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-debuginfo", rpm:"glibc-locale-base-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo", rpm:"glibc-utils-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-src-debugsource", rpm:"glibc-utils-src-debugsource~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd-debuginfo", rpm:"nscd-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-lang", rpm:"glibc-lang~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit-debuginfo", rpm:"glibc-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit-debuginfo", rpm:"glibc-devel-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static-32bit", rpm:"glibc-devel-static-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-32bit", rpm:"glibc-locale-base-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-32bit-debuginfo", rpm:"glibc-locale-base-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit", rpm:"glibc-utils-32bit~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit-debuginfo", rpm:"glibc-utils-32bit-debuginfo~2.31~150300.9.12.1", rls:"openSUSELeap15.3"))) {
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