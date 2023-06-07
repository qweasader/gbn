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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1663.1");
  script_cve_id("CVE-2017-9343", "CVE-2017-9344", "CVE-2017-9345", "CVE-2017-9346", "CVE-2017-9347", "CVE-2017-9348", "CVE-2017-9349", "CVE-2017-9350", "CVE-2017-9351", "CVE-2017-9352", "CVE-2017-9353", "CVE-2017-9354");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1663-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171663-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2017:1663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The network debugging tool wireshark was updated to version 2.2.7 to fix the following issues:
- CVE-2017-9352: Bazaar dissector infinite loop (wnpa-sec-2017-22)
 (bsc#1042304)
- CVE-2017-9348: DOF dissector read overflow (wnpa-sec-2017-23)
 (bsc#1042303)
- CVE-2017-9351: DHCP dissector read overflow (wnpa-sec-2017-24)
 (bsc#1042302)
- CVE-2017-9346: SoulSeek dissector infinite loop (wnpa-sec-2017-25)
 (bsc#1042301)
- CVE-2017-9345: DNS dissector infinite loop (wnpa-sec-2017-26)
 (bsc#1042300)
- CVE-2017-9349: DICOM dissector infinite loop (wnpa-sec-2017-27)
 (bsc#1042305)
- CVE-2017-9350: openSAFETY dissector memory exh.. (wnpa-sec-2017-28)
 (bsc#1042299)
- CVE-2017-9344: BT L2CAP dissector divide by zero (wnpa-sec-2017-29)
 (bsc#1042298)
- CVE-2017-9343: MSNIP dissector crash (wnpa-sec-2017-30) (bsc#1042309)
- CVE-2017-9347: ROS dissector crash (wnpa-sec-2017-31) (bsc#1042308)
- CVE-2017-9354: RGMP dissector crash (wnpa-sec-2017-32) (bsc#1042307)
- CVE-2017-9353: wireshark: IPv6 dissector crash (wnpa-sec-2017-33)
 (bsc#1042306)");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8-debuginfo", rpm:"libwireshark8-debuginfo~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6-debuginfo", rpm:"libwiretap6-debuginfo~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1-debuginfo", rpm:"libwscodecs1-debuginfo~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7-debuginfo", rpm:"libwsutil7-debuginfo~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.2.7~47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk-debuginfo", rpm:"wireshark-gtk-debuginfo~2.2.7~47.1", rls:"SLES12.0SP2"))) {
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
