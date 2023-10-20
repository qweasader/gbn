# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2121.1");
  script_cve_id("CVE-2019-16746", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-0305", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10769", "CVE-2020-10773", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-13974", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2121-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202121-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-0305: In cdev_get of char_dev.c, there is a possible
 use-after-free due to a race condition. This could lead to local
 escalation of privilege with System execution privileges needed. User
 interaction is not needed for exploitation (bnc#1174462).

CVE-2019-20908: An issue was discovered in drivers/firmware/efi/efi.c
 where incorrect access permissions for the efivar_ssdt ACPI variable
 could be used by attackers to bypass lockdown or secure boot
 restrictions, aka CID-1957a85b0032 (bnc#1173567).

CVE-2020-15780: An issue was discovered in drivers/acpi/acpi_configfs.c
 where injection of malicious ACPI tables via configfs could be used by
 attackers to bypass lockdown and secure boot restrictions, aka
 CID-75b0cea7bf30 (bnc#1173573).

CVE-2020-15393: usbtest_disconnect in drivers/usb/misc/usbtest.c has a
 memory leak, aka CID-28ebeb8db770 (bnc#1173514).

CVE-2020-12771: btree_gc_coalesce in drivers/md/bcache/btree.c had a
 deadlock if a coalescing operation fails (bnc#1171732).

CVE-2019-16746: net/wireless/nl80211.c did not check the length of
 variable elements in a beacon head, leading to a buffer overflow
 (bnc#1152107).

CVE-2020-12888: The VFIO PCI driver mishandled attempts to access
 disabled memory space (bnc#1171868).

CVE-2020-10769: A buffer over-read flaw was found in
 crypto_authenc_extractkeys in crypto/authenc.c in the IPsec
 Cryptographic algorithm's module, authenc. When a payload longer than 4
 bytes, and is not following 4-byte alignment boundary guidelines, it
 causes a buffer over-read threat, leading to a system crash. This flaw
 allowed a local attacker with user privileges to cause a denial of
 service (bnc#1173265).

CVE-2020-10773: A kernel stack information leak on s390/s390x was fixed
 (bnc#1172999).

CVE-2020-14416: A race condition in tty->disc_data handling in the slip
 and slcan line discipline could lead to a use-after-free, aka
 CID-0ace17d56824. This affects drivers/net/slip/slip.c and
 drivers/net/can/slcan.c (bnc#1162002).

CVE-2020-10768: Indirect branch speculation could have been enabled
 after it was force-disabled by the PR_SPEC_FORCE_DISABLE prctl command.
 (bnc#1172783).

CVE-2020-10766: Fixed Rogue cross-process SSBD shutdown, where a Linux
 scheduler logical bug allows an attacker to turn off the SSBD
 protection. (bnc#1172781).

CVE-2020-10767: Indirect Branch Prediction Barrier was force-disabled
 when STIBP is unavailable or enhanced IBRS is available. (bnc#1172782).

CVE-2020-13974: drivers/tty/vt/keyboard.c had an integer overflow if
 k_ascii is called several times in a row, aka CID-b86dab054059.
 (bnc#1172775).

CVE-2019-20810: go7007_snd_init in drivers/media/usb/go7007/snd-go7007.c
 in the Linux kernel did not call snd_card_free for a failure path, which
 causes a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.57.1", rls:"SLES12.0SP4"))) {
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
