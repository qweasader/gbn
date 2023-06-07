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
  script_oid("1.3.6.1.4.1.25623.1.0.123274");
  script_cve_id("CVE-2014-3615");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:36 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:10:07+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:10:07 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2014-1669)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1669");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1669.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2014-1669 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.3-60.el7_0.10]
- kvm-block-add-helper-function-to-determine-if-a-BDS-is-i.patch [bz#1122925]
- kvm-block-extend-block-commit-to-accept-a-string-for-the.patch [bz#1122925]
- kvm-block-add-backing-file-option-to-block-stream.patch [bz#1122925]
- kvm-block-add-__com.redhat_change-backing-file-qmp-comma.patch [bz#1122925]
- Resolves: bz#1122925
 (Maintain relative path to backing file image during live merge (block-commit))

[1.5.3-60.el7_0.9]
- kvm-scsi-disk-fix-bug-in-scsi_block_new_request-introduc.patch [bz#1141189]
- Resolves: bz#1141189
 (bug in scsi_block_new_request() function introduced by upstream commit 137745c5c60f083ec982fe9e861e8c16ebca1ba8)

[1.5.3-60.el7_0.8]
- kvm-vmstate_xhci_event-fix-unterminated-field-list.patch [bz#1145055]
- kvm-vmstate_xhci_event-bug-compat-with-RHEL-7.0-RHEL-onl.patch [bz#1145055]
- kvm-vbe-make-bochs-dispi-interface-return-the-correct-me.patch [bz#1139117]
- kvm-vbe-rework-sanity-checks.patch [bz#1139117]
- kvm-spice-display-add-display-channel-id-to-the-debug-me.patch [bz#1139117]
- kvm-spice-make-sure-we-don-t-overflow-ssd-buf.patch [bz#1139117]
- Resolves: bz#1139117
 (CVE-2014-3615 qemu-kvm: Qemu: crash when guest sets high resolution [rhel-7.0.z])
- Resolves: bz#1145055
 (vmstate_xhci_event: fix unterminated field list [rhel-7.0.z])");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.10", rls:"OracleLinux7"))) {
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
