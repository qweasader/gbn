# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0785.1");
  script_cve_id("CVE-2017-13166", "CVE-2017-15951", "CVE-2017-16644", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-17975", "CVE-2017-18208", "CVE-2018-1000026", "CVE-2018-1068", "CVE-2018-8087");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-10 15:19:19 +0000 (Tue, 10 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180785-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.120 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-13166: An elevation of privilege vulnerability in the v4l2
 video driver was fixed. (bnc#1072865).
- CVE-2017-15951: The KEYS subsystem did not correctly synchronize the
 actions of updating versus finding a key in the 'negative' state to
 avoid a race condition, which allowed local users to cause a denial of
 service or possibly have unspecified other impact via crafted system
 calls (bnc#1062840 bnc#1065615).
- CVE-2017-16644: The hdpvr_probe function in
 drivers/media/usb/hdpvr/hdpvr-core.c allowed local users to cause a
 denial of service (improper error handling and system crash) or possibly
 have unspecified other impact via a crafted USB device (bnc#1067118).
- CVE-2017-16912: The 'get_pipe()' function (drivers/usb/usbip/stub_rx.c)
 allowed attackers to cause a denial of service (out-of-bounds read) via
 a specially crafted USB over IP packet (bnc#1078673).
- CVE-2017-16913: The 'stub_recv_cmd_submit()' function
 (drivers/usb/usbip/stub_rx.c) when handling CMD_SUBMIT packets allowed
 attackers to cause a denial of service (arbitrary memory allocation) via
 a specially crafted USB over IP packet (bnc#1078672).
- CVE-2017-17975: Use-after-free in the usbtv_probe function in
 drivers/media/usb/usbtv/usbtv-core.c allowed attackers to cause a denial
 of service (system crash) or possibly have unspecified other impact by
 triggering failure of audio registration, because a kfree of the usbtv
 data structure occurs during a usbtv_video_free call, but the
 usbtv_video_fail label's code attempts to both access and free this data
 structure (bnc#1074426).
- CVE-2017-18208: The madvise_willneed function in mm/madvise.c allowed
 local users to cause a denial of service (infinite loop) by triggering
 use of MADVISE_WILLNEED for a DAX mapping (bnc#1083494).
- CVE-2018-8087: Memory leak in the hwsim_new_radio_nl function in
 drivers/net/wireless/mac80211_hwsim.c allowed local users to cause a
 denial of service (memory consumption) by triggering an out-of-array
 error case (bnc#1085053).
- CVE-2018-1000026: A insufficient input validation vulnerability in the
 bnx2x network card driver could result in DoS: Network card firmware
 assertion takes card off-line. This attack appear to be exploitable via
 An attacker on a must pass a very large, specially crafted packet to the
 bnx2x card. This can be done from an untrusted guest VM. (bnc#1079384).
- CVE-2018-1068: Insufficient user provided offset checking in the
 ebtables compat code allowed local attackers to overwrite kernel memory
 and potentially execute code. (bsc#1085107)
The following non-security bugs were fixed:
- acpi / bus: Leave modalias empty for devices which are not present
 (bnc#1012382).
- acpi: sbshc: remove raw pointer from printk() message (bnc#1012382).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
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
