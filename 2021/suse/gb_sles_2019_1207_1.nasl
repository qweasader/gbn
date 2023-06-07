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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1207.1");
  script_cve_id("CVE-2017-15134", "CVE-2017-15135", "CVE-2018-10850", "CVE-2018-10935", "CVE-2018-14624");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-15 21:29:00 +0000 (Wed, 15 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1207-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1207-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191207-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds' package(s) announced via the SUSE-SU-2019:1207-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 389-ds fixes the following issues:

The following security vulnerabilities were addressed:
CVE-2018-10850: Fixed a race condition on reference counter that would
 lead to a denial of service using persistent search (bsc#1096368)

CVE-2017-15134: Fixed a remote denial of service via search filters in
 slapi_filter_sprintf in slapd/util.c (bsc#1076530)

CVE-2017-15135: Fixed authentication bypass due to lack of size check in
 slapi_ct_memcmp function in ch_malloc.c (bsc#1076530)

CVE-2018-10935: Fixed an issue that allowed users to cause a crash via
 ldapsearch with server side sorts (bsc#1105606)

CVE-2018-14624: The lock controlling the error log was not correctly
 used when re-opening the log file in log__error_emergency(), allowing an
 attacker to send a flood of modifications to a very large DN, which
 could have caused slapd to crash (bsc#1106699).");

  script_tag(name:"affected", value:"'389-ds' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Server Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds", rpm:"389-ds~1.4.0.3~4.7.52", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debuginfo", rpm:"389-ds-debuginfo~1.4.0.3~4.7.52", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debugsource", rpm:"389-ds-debugsource~1.4.0.3~4.7.52", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-devel", rpm:"389-ds-devel~1.4.0.3~4.7.52", rls:"SLES15.0"))) {
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
