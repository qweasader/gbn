# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2358.1");
  script_cve_id("CVE-2021-3929", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-0216");
  script_tag(name:"creation_date", value:"2023-06-05 04:22:34 +0000 (Mon, 05 Jun 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-29 16:21:00 +0000 (Tue, 29 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2358-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2358-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232358-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2023:2358-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

CVE-2022-0216: Fixed a use-after-free in lsi_do_msgout() in hw/scsi/lsi53c895a.c (bsc#1198038).
CVE-2021-3929: Fixed use-after-free in nvme, caused by DMA reentrancy issue (bsc#1193880).
CVE-2021-4207: Fixed heap buffer overflow caused by double fetch in qxl_cursor() (bsc#1198037).
CVE-2021-4206: Fixed integer overflow in cursor_alloc() (bsc#1198035).
Amend .changes file: avoid declaring a still unfixed CVE, as fixed (bsc#1187529)
Fix the build breaks caused by binutils update (bsc#1192463, bsc#1193621)");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1_0_gb3ef39f~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1_0_gb3ef39f~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~2.6.2~41.76.1", rls:"SLES12.0SP2"))) {
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
