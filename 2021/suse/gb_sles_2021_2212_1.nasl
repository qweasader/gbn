# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2212.1");
  script_cve_id("CVE-2021-3544", "CVE-2021-3545", "CVE-2021-3546");
  script_tag(name:"creation_date", value:"2021-07-01 13:05:51 +0000 (Thu, 01 Jul 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 19:38:49 +0000 (Wed, 09 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2212-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212212-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2021:2212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

Security issues fixed:

CVE-2021-3546: Fix out-of-bounds write in virgl_cmd_get_capset
 (bsc#1185981)

CVE-2021-3544: Fix memory leaks found in the virtio vhost-user GPU
 device (bsc#1186010)

CVE-2021-3545: Fix information disclosure due to uninitialized memory
 read (bsc#1185990)

Non-security issues fixed:

Fix testsuite error (bsc#1184574)

Fix qemu crash with iothread when block commit after snapshot
 (bsc#1187013)

Fix qemu hang while cancelling migrating hugepage vm (bsc#1185591)

Use RCU to avoid race during scsi hotplug/hotunplug (bsc#1184574)");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE MicroOS 5.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-debuginfo", rpm:"qemu-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa-debuginfo", rpm:"qemu-audio-alsa-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa-debuginfo", rpm:"qemu-audio-pa-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0+~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-microvm", rpm:"qemu-microvm~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.12.1+~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses-debuginfo", rpm:"qemu-ui-curses-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk-debuginfo", rpm:"qemu-ui-gtk-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app-debuginfo", rpm:"qemu-ui-spice-app-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.12.1+~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~4.2.1~11.22.1", rls:"SLES15.0SP2"))) {
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
