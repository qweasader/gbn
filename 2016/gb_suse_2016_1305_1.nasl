# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851312");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-05-17 13:40:35 +0200 (Tue, 17 May 2016)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-1006", "CVE-2016-1011", "CVE-2016-1012", "CVE-2016-1013",
                "CVE-2016-1014", "CVE-2016-1015", "CVE-2016-1016", "CVE-2016-1017",
                "CVE-2016-1018", "CVE-2016-1019", "CVE-2016-1020", "CVE-2016-1021",
                "CVE-2016-1022", "CVE-2016-1023", "CVE-2016-1024", "CVE-2016-1025",
                "CVE-2016-1026", "CVE-2016-1027", "CVE-2016-1028", "CVE-2016-1029",
                "CVE-2016-1030", "CVE-2016-1031", "CVE-2016-1032", "CVE-2016-1033",
                "CVE-2016-1096", "CVE-2016-1097", "CVE-2016-1098", "CVE-2016-1099",
                "CVE-2016-1100", "CVE-2016-1101", "CVE-2016-1102", "CVE-2016-1103",
                "CVE-2016-1104", "CVE-2016-1105", "CVE-2016-1106", "CVE-2016-1107",
                "CVE-2016-1108", "CVE-2016-1109", "CVE-2016-1110", "CVE-2016-4108",
                "CVE-2016-4109", "CVE-2016-4110", "CVE-2016-4111", "CVE-2016-4112",
                "CVE-2016-4113", "CVE-2016-4114", "CVE-2016-4115", "CVE-2016-4116",
                "CVE-2016-4117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 20:10:00 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for flash-player (SUSE-SU-2016:1305-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flash-player fixes the following issues:

  - Security update to 11.2.202.621 (bsc#979422):

  * APSA16-02, APSB16-15, CVE-2016-1096, CVE-2016-1097, CVE-2016-1098,
  CVE-2016-1099, CVE-2016-1100, CVE-2016-1101, CVE-2016-1102,
  CVE-2016-1103, CVE-2016-1104, CVE-2016-1105, CVE-2016-1106,
  CVE-2016-1107, CVE-2016-1108, CVE-2016-1109, CVE-2016-1110,
  CVE-2016-4108, CVE-2016-4109, CVE-2016-4110, CVE-2016-4111,
  CVE-2016-4112, CVE-2016-4113, CVE-2016-4114, CVE-2016-4115,
  CVE-2016-4116, CVE-2016-4117

  - The following CVEs got fixed during the previous release, but got
  published afterwards:

  * APSA16-01, APSB16-10, CVE-2016-1006, CVE-2016-1011, CVE-2016-1012,
  CVE-2016-1013, CVE-2016-1014, CVE-2016-1015, CVE-2016-1016,
  CVE-2016-1017, CVE-2016-1018, CVE-2016-1019, CVE-2016-1020,
  CVE-2016-1021, CVE-2016-1022, CVE-2016-1023, CVE-2016-1024,
  CVE-2016-1025, CVE-2016-1026, CVE-2016-1027, CVE-2016-1028,
  CVE-2016-1029, CVE-2016-1030, CVE-2016-1031, CVE-2016-1032,
  CVE-2016-1033");

  script_tag(name:"affected", value:"flash-player on SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"SUSE-SU", value:"2016:1305-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.621~130.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.621~130.1", rls:"SLED12.0SP0"))) {
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
