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
  script_oid("1.3.6.1.4.1.25623.1.0.853438");
  script_version("2021-08-12T09:01:18+0000");
  script_cve_id("CVE-2020-15719");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-19 18:15:00 +0000 (Sat, 19 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-20 03:00:52 +0000 (Sun, 20 Sep 2020)");
  script_name("openSUSE: Security Advisory for openldap2 (openSUSE-SU-2020:1459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1459-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00059.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap2'
  package(s) announced via the openSUSE-SU-2020:1459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openldap2 fixes the following issues:

  - bsc#1174154 - CVE-2020-15719 - This resolves an issue with x509 SAN's
  falling back to CN validation in violation of rfc6125.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1459=1");

  script_tag(name:"affected", value:"'openldap2' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-debuginfo", rpm:"libldap-2_4-2-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta-debuginfo", rpm:"openldap2-back-meta-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-perl", rpm:"openldap2-back-perl~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-perl-debuginfo", rpm:"openldap2-back-perl-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-sock", rpm:"openldap2-back-sock~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-sock-debuginfo", rpm:"openldap2-back-sock-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-sql", rpm:"openldap2-back-sql~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-sql-debuginfo", rpm:"openldap2-back-sql-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client-debuginfo", rpm:"openldap2-client-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-contrib", rpm:"openldap2-contrib~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-contrib-debuginfo", rpm:"openldap2-contrib-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-debuginfo", rpm:"openldap2-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-debugsource", rpm:"openldap2-debugsource~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-devel", rpm:"openldap2-devel~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-devel-static", rpm:"openldap2-devel-static~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-ppolicy-check-password", rpm:"openldap2-ppolicy-check-password~1.2~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-ppolicy-check-password-debuginfo", rpm:"openldap2-ppolicy-check-password-debuginfo~1.2~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit-debuginfo", rpm:"libldap-2_4-2-32bit-debuginfo~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-devel-32bit", rpm:"openldap2-devel-32bit~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-data", rpm:"libldap-data~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-doc", rpm:"openldap2-doc~2.4.46~lp152.14.6.1", rls:"openSUSELeap15.2"))) {
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