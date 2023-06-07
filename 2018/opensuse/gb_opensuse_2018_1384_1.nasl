# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851757");
  script_version("2021-06-25T11:00:33+0000");
  script_tag(name:"last_modification", value:"2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-24 05:47:44 +0200 (Thu, 24 May 2018)");
  script_cve_id("CVE-2018-1046");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 15:58:00 +0000 (Mon, 31 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for pdns (openSUSE-SU-2018:1384-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pdns fixes the following issue:

  - CVE-2018-1046: An issue has been found in the dnsreplay tool provided
  with PowerDNS Authoritative, where replaying a specially crafted PCAP
  file can trigger a stack-based buffer
  overflow, leading to a crash and potentially arbitrary code execution.
  This buffer overflow only occurs when the -ecs-stamp
  option of dnsreplay is used. (boo#1092540)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-491=1");

  script_tag(name:"affected", value:"pdns on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1384-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00093.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geoip", rpm:"pdns-backend-geoip~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geoip-debuginfo", rpm:"pdns-backend-geoip-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-godbc", rpm:"pdns-backend-godbc~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-godbc-debuginfo", rpm:"pdns-backend-godbc-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap-debuginfo", rpm:"pdns-backend-ldap-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-lua", rpm:"pdns-backend-lua~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-lua-debuginfo", rpm:"pdns-backend-lua-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mydns", rpm:"pdns-backend-mydns~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mydns-debuginfo", rpm:"pdns-backend-mydns-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql-debuginfo", rpm:"pdns-backend-mysql-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-postgresql", rpm:"pdns-backend-postgresql~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-postgresql-debuginfo", rpm:"pdns-backend-postgresql-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-remote", rpm:"pdns-backend-remote~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-remote-debuginfo", rpm:"pdns-backend-remote-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite3", rpm:"pdns-backend-sqlite3~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite3-debuginfo", rpm:"pdns-backend-sqlite3-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-debuginfo", rpm:"pdns-debuginfo~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-debugsource", rpm:"pdns-debugsource~4.0.3~12.1", rls:"openSUSELeap42.3"))) {
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
