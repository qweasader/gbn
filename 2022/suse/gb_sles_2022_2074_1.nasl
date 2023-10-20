# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2074.1");
  script_cve_id("CVE-2021-3695", "CVE-2021-3696", "CVE-2021-3697", "CVE-2022-28733", "CVE-2022-28734", "CVE-2022-28735", "CVE-2022-28736");
  script_tag(name:"creation_date", value:"2022-06-15 04:32:10 +0000 (Wed, 15 Jun 2022)");
  script_version("2023-07-31T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-07-31 05:06:15 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-28 15:34:00 +0000 (Fri, 28 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2074-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222074-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the SUSE-SU-2022:2074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 fixes the following issues:

Security fixes and hardenings for boothole 3 / boothole 2022 (bsc#1198581)

CVE-2021-3695: Fixed that a crafted PNG grayscale image could lead to
 out-of-bounds write in heap (bsc#1191184)

CVE-2021-3696: Fixed that a crafted PNG image could lead to out-of-bound
 write during huffman table handling (bsc#1191185)

CVE-2021-3697: Fixed that a crafted JPEG image could lead to buffer
 underflow write in the heap (bsc#1191186)

CVE-2022-28733: Fixed fragmentation math in net/ip (bsc#1198460)

CVE-2022-28734: Fixed an out-of-bound write for split http headers
 (bsc#1198493)

CVE-2022-28735: Fixed some verifier framework changes (bsc#1198495)

CVE-2022-28736: Fixed a use-after-free in chainloader command
 (bsc#1198496)

Update SBAT security contact (bsc#1193282)

Bump grub's SBAT generation to 2

Use boot disks in OpenFirmware, fixing regression caused when the root
 LV is completely in the boot LUN (bsc#1197948)");

  script_tag(name:"affected", value:"'grub2' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-arm64-efi", rpm:"grub2-arm64-efi~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-debuginfo", rpm:"grub2-debuginfo~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-debugsource", rpm:"grub2-debugsource~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-pc", rpm:"grub2-i386-pc~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-powerpc-ieee1275", rpm:"grub2-powerpc-ieee1275~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-s390x-emu", rpm:"grub2-s390x-emu~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-snapper-plugin", rpm:"grub2-snapper-plugin~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-systemd-sleep-plugin", rpm:"grub2-systemd-sleep-plugin~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-xen", rpm:"grub2-x86_64-xen~2.04~150200.9.63.2", rls:"SLES15.0SP2"))) {
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
