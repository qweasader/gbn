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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0227");
  script_cve_id("CVE-2014-0155", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0227");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0227.html");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.20");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.19");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13395");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-rt' package(s) announced via the MGASA-2014-0227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel-rt provides upstream 3.12.20 kernel and fixes the
following security issues:

The ioapic_deliver function in virt/kvm/ioapic.c in the Linux kernel
through 3.14.1 does not properly validate the kvm_irq_delivery_to_apic
return value, which allows guest OS users to cause a denial of service
(host OS crash) via a crafted entry in the redirection table of an I/O
APIC. NOTE: the affected code was moved to the ioapic_service function
before the vulnerability was announced. (CVE-2014-0155)

The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel
through 3.14.3 does not properly manage tty driver access in the
'LECHO & !OPOST' case, which allows local users to cause a denial of
service (memory corruption and system crash) or gain privileges by
triggering a race condition involving read and write operations with
long strings. (CVE-2014-0196)

The raw_cmd_copyin function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly handle error conditions during
processing of an FDRAWCMD ioctl call, which allows local users to trigger
kfree operations and gain privileges by leveraging write access to a
/dev/fd device. (CVE-2014-1737)

The raw_cmd_copyout function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly restrict access to certain
pointers during processing of an FDRAWCMD ioctl call, which allows
local users to obtain sensitive information from kernel heap memory
by leveraging write access to a /dev/fd device. (CVE-2014-1738)

The -rt patch has been updated to rt30.

For other fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-rt' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-3.12.20-0.rt30.1.mga4", rpm:"kernel-rt-3.12.20-0.rt30.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~3.12.20~0.rt30.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-3.12.20-0.rt30.1.mga4", rpm:"kernel-rt-devel-3.12.20-0.rt30.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-latest", rpm:"kernel-rt-devel-latest~3.12.20~0.rt30.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~3.12.20~0.rt30.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-latest", rpm:"kernel-rt-latest~3.12.20~0.rt30.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-3.12.20-0.rt30.1.mga4", rpm:"kernel-rt-source-3.12.20-0.rt30.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-latest", rpm:"kernel-rt-source-latest~3.12.20~0.rt30.1.mga4", rls:"MAGEIA4"))) {
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
