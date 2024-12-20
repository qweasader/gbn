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
  script_oid("1.3.6.1.4.1.25623.1.0.854092");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2021-20298", "CVE-2021-20299", "CVE-2021-20300", "CVE-2021-20302", "CVE-2021-20303", "CVE-2021-20304", "CVE-2021-3476");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 16:10:00 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"creation_date", value:"2021-08-21 03:01:57 +0000 (Sat, 21 Aug 2021)");
  script_name("openSUSE: Security Advisory for openexr (openSUSE-SU-2021:2793-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2793-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I6OVSOAQ3PQXBTM46SMNT6H3XP45CC7L");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2021:2793-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr fixes the following issues:

  - CVE-2021-20298 [bsc#1188460]: Fixed Out-of-memory in B44Compressor

  - CVE-2021-20299 [bsc#1188459]: Fixed Null-dereference READ in
       Imf_2_5:Header:operator

  - CVE-2021-20300 [bsc#1188458]: Fixed Integer-overflow in
       Imf_2_5:hufUncompress

  - CVE-2021-20302 [bsc#1188462]: Fixed Floating-point-exception in
       Imf_2_5:precalculateTileInfot

  - CVE-2021-20303 [bsc#1188457]: Fixed Heap-buffer-overflow in
       Imf_2_5::copyIntoFrameBuffer

  - CVE-2021-20304 [bsc#1188461]: Fixed Undefined-shift in Imf_2_5:hufDecode");

  script_tag(name:"affected", value:"'openexr' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23", rpm:"libIlmImf-2_2-23~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-debuginfo", rpm:"libIlmImf-2_2-23-debuginfo~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23", rpm:"libIlmImfUtil-2_2-23~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-debuginfo", rpm:"libIlmImfUtil-2_2-23-debuginfo~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debuginfo", rpm:"openexr-debuginfo~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debugsource", rpm:"openexr-debugsource~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-devel", rpm:"openexr-devel~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-doc", rpm:"openexr-doc~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit", rpm:"libIlmImf-2_2-23-32bit~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit-debuginfo", rpm:"libIlmImf-2_2-23-32bit-debuginfo~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit", rpm:"libIlmImfUtil-2_2-23-32bit~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit-debuginfo", rpm:"libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~3.35.1", rls:"openSUSELeap15.3"))) {
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