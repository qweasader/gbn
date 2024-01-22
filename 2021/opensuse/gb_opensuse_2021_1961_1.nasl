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
  script_oid("1.3.6.1.4.1.25623.1.0.853944");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-25097", "CVE-2021-28651", "CVE-2021-28652", "CVE-2021-28662", "CVE-2021-31806");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:04:39 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for squid (openSUSE-SU-2021:1961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1961-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PR56WJLXVU76BKBW5SFENNPKF5TJSS5K");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the openSUSE-SU-2021:1961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid fixes the following issues:

  - update to 4.15:

  - CVE-2021-28652: Broken cache manager URL parsing (bsc#1185918)

  - CVE-2021-28651: Memory leak in RFC 2169 response parsing (bsc#1185921)

  - CVE-2021-28662: Limit HeaderLookupTable_t::lookup() to BadHdr and
       specific IDs (bsc#1185919)

  - CVE-2021-31806: Handle more Range requests (bsc#1185916)

  - CVE-2020-25097: HTTP Request Smuggling vulnerability (bsc#1183436)

  - Handle more partial responses (bsc#1185923)

  - fix previous change to reinstante permissions macros, because the wrong
       path has been used (bsc#1171569).

  - use libexecdir instead of libdir to conform to recent changes in Factory
       (bsc#1171164).

  - Reinstate permissions macros for pinger binary, because the permissions
       package is also responsible for setting up the cap_net_raw capability,
       currently a fresh squid install doesn&#x27 t get a capability bit at all
       (bsc#1171569).

  - Change pinger and basic_pam_auth helper to use standard permissions.
       pinger uses cap_net_raw=ep instead (bsc#1171569)");

  script_tag(name:"affected", value:"'squid' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.15~5.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~4.15~5.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~4.15~5.26.1", rls:"openSUSELeap15.3"))) {
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