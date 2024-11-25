# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0346");
  script_cve_id("CVE-2013-2015", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4254", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0346");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0346.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11468");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.53");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.54");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.55");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.56");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.57");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.58");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.59");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.60");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.61");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.62");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.63");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.64");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.65");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.66");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.67");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.68");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.69");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-vserver' package(s) announced via the MGASA-2013-0346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-vserver update provides the upstream 3.4.69 kernel and fixes the
following security issues:

The ext4_orphan_del function in fs/ext4/namei.c in the Linux kernel before
3.7.3 does not properly handle orphan-list entries for non-journal
filesystems, which allows physically proximate attackers to cause a denial
of service (system hang) via a crafted filesystem on removable media, as
demonstrated by the e2fsprogs tests/f_orphan_extents_inode/image.gz test
(CVE-2013-2015).

Multiple array index errors in drivers/hid/hid-core.c in the Human
Interface Device (HID) subsystem in the Linux kernel through 3.11 allow
physically proximate attackers to execute arbitrary code or cause a
denial of service (heap memory corruption) via a crafted device that
provides an invalid Report ID (CVE-2013-2888).

drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem
in the Linux kernel through 3.11, when CONFIG_HID_ZEROPLUS is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2889).

drivers/hid/hid-pl.c in the Human Interface Device (HID) subsystem in
the Linux kernel through 3.11, when CONFIG_HID_PANTHERLORD is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2892).

The Human Interface Device (HID) subsystem in the Linux kernel
through 3.11, when CONFIG_LOGITECH_FF, CONFIG_LOGIG940_FF, or
CONFIG_LOGIWHEELS_FF is enabled, allows physically proximate
attackers to cause a denial of service (heap-based out-of-bounds
write) via a crafted device, related to (1) drivers/hid/hid-lgff.c,
(2) drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c
(CVE-2013-2893).

drivers/hid/hid-logitech-dj.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_LOGITECH_DJ
is enabled, allows physically proximate attackers to cause a denial
of service (NULL pointer dereference and OOPS) or obtain sensitive
information from kernel memory via a crafted device (CVE-2013-2895).

drivers/hid/hid-ntrig.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_NTRIG
is enabled, allows physically proximate attackers to cause a denial
of service (NULL pointer dereference and OOPS) via a crafted device
(CVE-2013-2896).

Multiple array index errors in drivers/hid/hid-multitouch.c in the
Human Interface Device (HID) subsystem in the Linux kernel through
3.11, when CONFIG_HID_MULTITOUCH is enabled, allow physically proximate
attackers to cause a denial of service (heap memory corruption, or NULL
pointer dereference and OOPS) via a crafted device (CVE-2013-2897).

drivers/hid/hid-picolcd_core.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_PICOLCD
is enabled, allows physically proximate attackers ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-vserver' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-3.4.69-1.mga2", rpm:"kernel-vserver-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver", rpm:"kernel-vserver~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-3.4.69-1.mga2", rpm:"kernel-vserver-devel-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-devel-latest", rpm:"kernel-vserver-devel-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-doc", rpm:"kernel-vserver-doc~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-latest", rpm:"kernel-vserver-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-3.4.69-1.mga2", rpm:"kernel-vserver-source-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vserver-source-latest", rpm:"kernel-vserver-source-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
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
