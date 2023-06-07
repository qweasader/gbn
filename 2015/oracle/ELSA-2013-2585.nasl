# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.123511");
  script_cve_id("CVE-2012-6545", "CVE-2013-0343", "CVE-2013-1928", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-3231", "CVE-2013-4345", "CVE-2013-4591");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T06:57:19+0000");
  script_tag(name:"last_modification", value:"2022-04-05 06:57:19 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-2585)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2585");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2585.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, mlnx_en-2.6.32-400.33.3.el5uek, mlnx_en-2.6.32-400.33.3.el6uek, ofa-2.6.32-400.33.3.el5uek, ofa-2.6.32-400.33.3.el6uek' package(s) announced via the ELSA-2013-2585 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[2.6.32-400.33.3uek]
- af_key: fix info leaks in notify messages (Mathias Krause) [Orabug: 17837974] {CVE-2013-2234}
- drivers/cdrom/cdrom.c: use kzalloc() for failing hardware (Jonathan Salwan) [Orabug: 17837971] {CVE-2013-2164}
- fs/compat_ioctl.c: VIDEO_SET_SPU_PALETTE missing error check (Kees Cook) [Orabug: 17837966] {CVE-2013-1928}
- Bluetooth: RFCOMM - Fix info leak in ioctl(RFCOMMGETDEVLIST) (Mathias Krause) [Orabug: 17837959] {CVE-2012-6545}
- Bluetooth: RFCOMM - Fix info leak via getsockname() (Mathias Krause) [Orabug: 17838023] {CVE-2012-6545}
- llc: Fix missing msg_namelen update in llc_ui_recvmsg() (Mathias Krause) [Orabug: 17837945] {CVE-2013-3231}
- HID: pantherlord: validate output report details (Kees Cook) [Orabug: 17837942] {CVE-2013-2892}
- HID: zeroplus: validate output report details (Kees Cook) [Orabug: 17837936] {CVE-2013-2889}
- HID: provide a helper for validating hid reports (Kees Cook) [Orabug: 17837936]
- NFSv4: Check for buffer length in __nfs4_get_acl_uncached (Sven Wegener) [Orabug: 17837931] {CVE-2013-4591}
- ansi_cprng: Fix off by one error in non-block size request (Neil Horman) [Orabug: 17837999] {CVE-2013-4345}
- HID: validate HID report id size (Kees Cook) [Orabug: 17837925] {CVE-2013-2888}
- ipv6: remove max_addresses check from ipv6_create_tempaddr (Hannes Frederic Sowa) [Orabug: 17837923] {CVE-2013-0343}");

  script_tag(name:"affected", value:"'kernel-uek, mlnx_en-2.6.32-400.33.3.el5uek, mlnx_en-2.6.32-400.33.3.el6uek, ofa-2.6.32-400.33.3.el5uek, ofa-2.6.32-400.33.3.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.33.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.33.3.el5uek", rpm:"mlnx_en-2.6.32-400.33.3.el5uek~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.33.3.el5uekdebug", rpm:"mlnx_en-2.6.32-400.33.3.el5uekdebug~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.33.3.el5uek", rpm:"ofa-2.6.32-400.33.3.el5uek~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.33.3.el5uekdebug", rpm:"ofa-2.6.32-400.33.3.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.33.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.33.3.el6uek", rpm:"mlnx_en-2.6.32-400.33.3.el6uek~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.33.3.el6uekdebug", rpm:"mlnx_en-2.6.32-400.33.3.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.33.3.el6uek", rpm:"ofa-2.6.32-400.33.3.el6uek~1.5.1~4.0.58", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.33.3.el6uekdebug", rpm:"ofa-2.6.32-400.33.3.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6"))) {
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
