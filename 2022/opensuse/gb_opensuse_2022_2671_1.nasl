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
  script_oid("1.3.6.1.4.1.25623.1.0.854882");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-1705", "CVE-2022-1962", "CVE-2022-28131", "CVE-2022-30630", "CVE-2022-30631", "CVE-2022-30632", "CVE-2022-30633", "CVE-2022-30635", "CVE-2022-32148", "CVE-2022-32189");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-15 13:44:00 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-05 01:01:57 +0000 (Fri, 05 Aug 2022)");
  script_name("openSUSE: Security Advisory for go1.17 (SUSE-SU-2022:2671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2671-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UBLF3UDSD77TBEY3S2W3S7IGDSZS7VVE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.17'
  package(s) announced via the SUSE-SU-2022:2671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.17 fixes the following issues:
  Update to go version 1.17.13 (bsc#1190649):

  - CVE-2022-32189: encoding/gob, math/big: decoding big.Float and big.Rat
       can panic (bsc#1202035).

  - CVE-2022-30635: encoding/gob: stack exhaustion in Decoder.Decode
       (bsc#1201444).

  - CVE-2022-30631: compress/gzip: stack exhaustion in Reader.Read
       (bsc#1201437).

  - CVE-2022-1962: go/parser: stack exhaustion in all Parse* functions
       (bsc#1201448).

  - CVE-2022-28131: encoding/xml: stack exhaustion in Decoder.Skip
       (bsc#1201443).

  - CVE-2022-1705: net/http: improper sanitization of Transfer-Encoding
       header (bsc#1201434)

  - CVE-2022-30630: io/fs: stack exhaustion in Glob (bsc#1201447).

  - CVE-2022-32148: net/http/httputil: NewSingleHostReverseProxy - omit
       X-Forwarded-For not working (bsc#1201436)

  - CVE-2022-30632: path/filepath: stack exhaustion in Glob (bsc#1201445).

  - CVE-2022-30633: encoding/xml: stack exhaustion in Unmarshal
       (bsc#1201440).");

  script_tag(name:"affected", value:"'go1.17' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.17", rpm:"go1.17~1.17.13~150000.1.42.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-doc", rpm:"go1.17-doc~1.17.13~150000.1.42.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-race", rpm:"go1.17-race~1.17.13~150000.1.42.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.17", rpm:"go1.17~1.17.13~150000.1.42.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-doc", rpm:"go1.17-doc~1.17.13~150000.1.42.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-race", rpm:"go1.17-race~1.17.13~150000.1.42.1", rls:"openSUSELeap15.3"))) {
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