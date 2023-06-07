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
  script_oid("1.3.6.1.4.1.25623.1.0.853738");
  script_version("2021-08-26T12:01:05+0000");
  script_cve_id("CVE-2020-8625");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-19 22:15:00 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:26 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for bind (openSUSE-SU-2021:0375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0375-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WTREZMKE6OIOIY3CLBWV3GIOPB4EM4DX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the openSUSE-SU-2021:0375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  - CVE-2020-8625: A vulnerability in BIND&#x27 s GSSAPI security policy
       negotiation can be targeted by a buffer overflow attack [bsc#1182246]

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600", rpm:"libbind9-1600~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-debuginfo", rpm:"libbind9-1600-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605", rpm:"libdns1605~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-debuginfo", rpm:"libdns1605-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs-devel", rpm:"libirs-devel~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601", rpm:"libirs1601~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-debuginfo", rpm:"libirs1601-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606", rpm:"libisc1606~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-debuginfo", rpm:"libisc1606-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600", rpm:"libisccc1600~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-debuginfo", rpm:"libisccc1600-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600", rpm:"libisccfg1600~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-debuginfo", rpm:"libisccfg1600-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604", rpm:"libns1604~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-debuginfo", rpm:"libns1604-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel-32bit", rpm:"bind-devel-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit", rpm:"libbind9-1600-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit-debuginfo", rpm:"libbind9-1600-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit", rpm:"libdns1605-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit-debuginfo", rpm:"libdns1605-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit", rpm:"libirs1601-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit-debuginfo", rpm:"libirs1601-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit", rpm:"libisc1606-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit-debuginfo", rpm:"libisc1606-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit", rpm:"libisccc1600-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit-debuginfo", rpm:"libisccc1600-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit", rpm:"libisccfg1600-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit-debuginfo", rpm:"libisccfg1600-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit", rpm:"libns1604-32bit~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit-debuginfo", rpm:"libns1604-32bit-debuginfo~9.16.6~lp152.14.12.1", rls:"openSUSELeap15.2"))) {
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