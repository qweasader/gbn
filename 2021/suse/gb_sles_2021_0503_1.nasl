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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0503.1");
  script_cve_id("CVE-2020-8625");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-19 22:15:00 +0000 (Fri, 19 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0503-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210503-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2021:0503-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

CVE-2020-8625: A vulnerability in BIND's GSSAPI security policy
 negotiation can be targeted by a buffer overflow attack [bsc#1182246,
 CVE-2020-8625]");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161", rpm:"libbind9-161~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161-debuginfo", rpm:"libbind9-161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110", rpm:"libdns1110~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110-debuginfo", rpm:"libdns1110-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161", rpm:"libirs161~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161-debuginfo", rpm:"libirs161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-32bit", rpm:"libisc1107-32bit~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107", rpm:"libisc1107~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo-32bit", rpm:"libisc1107-debuginfo-32bit~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo", rpm:"libisc1107-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161", rpm:"libisccc161~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161-debuginfo", rpm:"libisccc161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163", rpm:"libisccfg163~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163-debuginfo", rpm:"libisccfg163-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161", rpm:"liblwres161~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161-debuginfo", rpm:"liblwres161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-bind", rpm:"python-bind~9.11.22~3.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161", rpm:"libbind9-161~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161-debuginfo", rpm:"libbind9-161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110", rpm:"libdns1110~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110-debuginfo", rpm:"libdns1110-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161", rpm:"libirs161~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161-debuginfo", rpm:"libirs161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-32bit", rpm:"libisc1107-32bit~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107", rpm:"libisc1107~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo-32bit", rpm:"libisc1107-debuginfo-32bit~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo", rpm:"libisc1107-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161", rpm:"libisccc161~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161-debuginfo", rpm:"libisccc161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163", rpm:"libisccfg163~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163-debuginfo", rpm:"libisccfg163-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161", rpm:"liblwres161~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161-debuginfo", rpm:"liblwres161-debuginfo~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-bind", rpm:"python-bind~9.11.22~3.29.1", rls:"SLES12.0SP5"))) {
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
