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
  script_oid("1.3.6.1.4.1.25623.1.0.122851");
  script_cve_id("CVE-2016-0728");
  script_tag(name:"creation_date", value:"2016-01-21 05:29:49 +0000 (Thu, 21 Jan 2016)");
  script_version("2023-01-18T10:11:02+0000");
  script_tag(name:"last_modification", value:"2023-01-18 10:11:02 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:40:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Oracle: Security Advisory (ELSA-2016-3510)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-3510");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-3510.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-4.1.12-32.1.2.el6uek, dtrace-modules-4.1.12-32.1.2.el7uek, kernel-uek' package(s) announced via the ELSA-2016-3510 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[4.1.12-32.1.2]
- KEYS: Fix keyring ref leak in join_session_keyring() (Yevgeny Pats) [Orabug: 22563965] {CVE-2016-0728}

[4.1.12-32.1.1]
- ocfs2: return non-zero st_blocks for inline data (John Haxby) [Orabug: 22218243]
- xen/events/fifo: Consume unprocessed events when a CPU dies (Ross Lagerwall) [Orabug: 22498877]
- Revert 'xen/fb: allow xenfb initialization for hvm guests' (Konrad Rzeszutek Wilk)
- xen/pciback: Don't allow MSI-X ops if PCI_COMMAND_MEMORY is not set. (Konrad Rzeszutek Wilk)
- xen/pciback: For XEN_PCI_OP_disable_msi[<pipe>x] only disable if device has MSI(X) enabled. (Konrad Rzeszutek Wilk)
- xen/pciback: Do not install an IRQ handler for MSI interrupts. (Konrad Rzeszutek Wilk)
- xen/pciback: Return error on XEN_PCI_OP_enable_msix when device has MSI or MSI-X enabled (Konrad Rzeszutek Wilk)
- xen/pciback: Return error on XEN_PCI_OP_enable_msi when device has MSI or MSI-X enabled (Konrad Rzeszutek Wilk)
- xen/pciback: Save xen_pci_op commands before processing it (Konrad Rzeszutek Wilk)
- xen-scsiback: safely copy requests (David Vrabel)
- xen-blkback: read from indirect descriptors only once (Roger Pau Monne)
- xen-blkback: only read request operation from shared ring once (Roger Pau Monne)
- xen-netback: use RING_COPY_REQUEST() throughout (David Vrabel)
- xen-netback: don't use last request to determine minimum Tx credit (David Vrabel)
- xen: Add RING_COPY_REQUEST() (David Vrabel)");

  script_tag(name:"affected", value:"'dtrace-modules-4.1.12-32.1.2.el6uek, dtrace-modules-4.1.12-32.1.2.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-4.1.12-32.1.2.el6uek", rpm:"dtrace-modules-4.1.12-32.1.2.el6uek~0.5.1~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~4.1.12~32.1.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~4.1.12~32.1.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~4.1.12~32.1.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~4.1.12~32.1.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~4.1.12~32.1.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~4.1.12~32.1.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-4.1.12-32.1.2.el7uek", rpm:"dtrace-modules-4.1.12-32.1.2.el7uek~0.5.1~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~4.1.12~32.1.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~4.1.12~32.1.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~4.1.12~32.1.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~4.1.12~32.1.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~4.1.12~32.1.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~4.1.12~32.1.2.el7uek", rls:"OracleLinux7"))) {
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
