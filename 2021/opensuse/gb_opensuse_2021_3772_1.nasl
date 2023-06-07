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
  script_oid("1.3.6.1.4.1.25623.1.0.854319");
  script_version("2021-11-29T14:44:44+0000");
  script_cve_id("CVE-2021-32626", "CVE-2021-32627", "CVE-2021-32628", "CVE-2021-32672", "CVE-2021-32675", "CVE-2021-32687", "CVE-2021-32762", "CVE-2021-41099");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-11-29 14:44:44 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-13 17:08:00 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-11-25 02:02:55 +0000 (Thu, 25 Nov 2021)");
  script_name("openSUSE: Security Advisory for redis (openSUSE-SU-2021:3772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3772-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OTFIHYYQFTTATMKJQIWNX7F7WKXQXYDB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis'
  package(s) announced via the openSUSE-SU-2021:3772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis fixes the following issues:

  - CVE-2021-32627: Fixed integer to heap buffer overflows with streams
       (bsc#1191305).

  - CVE-2021-32628: Fixed integer to heap buffer overflows handling
       ziplist-encoded data types (bsc#1191305).

  - CVE-2021-32687: Fixed integer to heap buffer overflow with intsets
       (bsc#1191302).

  - CVE-2021-32762: Fixed integer to heap buffer overflow issue in redis-cli
       and redis-sentinel (bsc#1191300).

  - CVE-2021-32626: Fixed heap buffer overflow caused by specially crafted
       Lua scripts (bsc#1191306).

  - CVE-2021-32672: Fixed random heap reading issue with Lua Debugger
       (bsc#1191304).

  - CVE-2021-32675: Fixed Denial Of Service when processing RESP request
       payloads with a large number of elements on many connections
       (bsc#1191303).

  - CVE-2021-41099: Fixed integer to heap buffer overflow handling certain
       string commands and network payloads (bsc#1191299).");

  script_tag(name:"affected", value:"'redis' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.14~6.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~6.0.14~6.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~6.0.14~6.8.1", rls:"openSUSELeap15.3"))) {
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