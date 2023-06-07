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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3368.1");
  script_cve_id("CVE-2020-28362", "CVE-2020-28366", "CVE-2020-28367");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-16 03:15:00 +0000 (Wed, 16 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3368-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203368-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.15' package(s) announced via the SUSE-SU-2020:3368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.15 fixes the following issues:

go1.15.5 (released 2020-11-12) includes security fixes to the cmd/go and
 math/big packages.
 * go#42553 math/big: panic during recursive division of very large
 numbers (bsc#1178750 CVE-2020-28362)
 * go#42560 cmd/go: arbitrary code can be injected into cgo generated
 files (bsc#1178752 CVE-2020-28367)
 * go#42557 cmd/go: improper validation of cgo flags can lead to remote
 code execution at build time (bsc#1178753 CVE-2020-28366)
 * go#42169 cmd/compile, runtime, reflect: pointers to go:notinheap types
 must be stored indirectly in interfaces
 * go#42151 cmd/cgo: opaque struct pointers are broken since Go 1.15.3
 * go#42138 time: Location interprets wrong timezone (DST) with slim
 zoneinfo
 * go#42113 x/net/http2: the first write error on a connection will cause
 all subsequent write requests to fail blindly
 * go#41914 net/http: request.Clone doesn't deep copy TransferEncoding
 * go#41704 runtime: macOS syscall.Exec can get SIGILL due to preemption
 signal
 * go#41463 compress/flate: deflatefast produces corrupted output
 * go#41387 x/net/http2: connection-level flow control not returned if
 stream errors, causes server hang
 * go#40974 cmd/link: sectionForAddress(0xA9D67F) address not in any
 section file");

  script_tag(name:"affected", value:"'go1.15' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.5~1.11.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.5~1.11.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.5~1.11.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.5~1.11.1", rls:"SLES15.0SP2"))) {
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
