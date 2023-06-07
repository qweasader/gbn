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
  script_oid("1.3.6.1.4.1.25623.1.0.123962");
  script_cve_id("CVE-2011-4347");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:53 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T06:57:19+0000");
  script_tag(name:"last_modification", value:"2022-04-05 06:57:19 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0149)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0149");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0149.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2012-0149 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-249.0.1.el5]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch
- Added kvm-Introduce-oel-machine-type.patch
- modify kversion to fix build failure

[kvm-83-249.el5]
- kvm-kernel-KVM-x86-Prevent-starting-PIT-timers-in-the-absence-o.patch [bz#770101]
- CVE: CVE-2011-4622
- Resolves: bz#770101
 (CVE-2011-4622 kernel: kvm: pit timer with no irqchip crashes the system [rhel-5.8])

[kvm-83-248.el5]
- kvm-e1000-prevent-buffer-overflow-when-processing-legacy.patch [bz#772080]
- CVE: CVE-2012-0029
- Resolves: bz#772080
 (EMBARGOED CVE-2012-0029 qemu-kvm: e1000: process_tx_desc legacy mode packets heap overflow [rhel-5.8])

[kvm-83-247.el5]
- kvm-kernel-KVM-Remove-ability-to-assign-a-device-without-iommu-.patch [bz#770095]
- kvm-kernel-KVM-Device-assignment-permission-checks.patch [bz#770095]
- Resolves: bz#770095
 (CVE-2011-4347 kernel: kvm: device assignment DoS [rhel-5.8])

[kvm-83-246.el5]
- kvm-Fix-SIGFPE-for-vnc-display-of-width-height-1.patch [bz#751482]
- Resolves: bz#751482
 (Backport SIGFPE fix in qemu-kvm VNC to RHEL5.x)

[kvm-83-245.el5]
- kvm-Fix-external-module-compat.c-not-to-use-unsupported-.patch [bz#753860]
- Resolves: bz#753860
 (Fix kvm userspace compilation on RHEL-5 to match the kernel changes)

[kvm-83-244.el5]
- kvm-do-not-change-RTC-stored-time-accidentally.patch [bz#703335]
- Resolves: bz#703335
 (KVM guest clocks jump forward one hour on reboot)

[kvm-83-243.el5]
- kvm-e1000-multi-buffer-packet-support.patch [bz#703446]
- kvm-e1000-clear-EOP-for-multi-buffer-descriptors.patch [bz#703446]
- kvm-e1000-verify-we-have-buffers-upfront.patch [bz#703446]
- kvm-BZ725876-make-RTC-alarm-work.patch [bz#725876]
- kvm-BZ725876-fix-RTC-polling-mode.patch [bz#725876]
- Resolves: bz#703446
 (Failed to ping guest after MTU is changed)
- Resolves: bz#725876
 (RTC interrupt problems with RHEL5 qemu/kvm (0.10 based) on 2.6.38+ guest kernels.)

[kvm-83-242.el5]
- kvm-posix-aio-compat-fix-latency-issues.patch [bz#725629]
- Resolves: bz#725629
 (RHEL5.5 KVM VMs freezing for a few seconds)

[kvm-83-241.el5]
- kvm-pci-assign-limit-number-of-assigned-devices-via-hotp.patch [bz#701616]
- kvm-pci-assign-Cleanup-file-descriptors.patch [bz#700281]
- Resolves: bz#700281
 ([Intel 5.8 Bug] Fail to attach/detach NIC more than 250 times)
- Resolves: bz#701616
 (limitation on max number of assigned devices does not take effect if hot-plug pci devices)

[kvm-83-240.el5]
- Updated kversion to 2.6.18-275.el to match build root
- kvm-Fix-vga-segfaults-or-screen-corruption-with-large-me.patch [bz#704081]
- Resolves: bz#704081
 (mouse responds very slowly with huge memory)");

  script_tag(name:"affected", value:"'kvm' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~249.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~249.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~249.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~249.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~249.0.1.el5", rls:"OracleLinux5"))) {
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
