# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3179.1");
  script_cve_id("CVE-2019-14818");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3179-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193179-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2019:3179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of dpdk to version 18.11.3 provides the following fixes:

dpdk was updated to 18.11.3 (fate#327817, bsc#1145713, jsc#ECO-274,
fate#325916, fate#325951 fate#326025, fate#326992, bsc#1134968,
jsc#SLE-4715)

Security issue fixed:
CVE-2019-14818: Fixed a memory leak vulnerability caused by a malicius
 container may lead to denial of service (bsc#1156146).

Other issues addressed:
Fixed a regression by inserting version numbers to the drivers
 (bsc#1157179).

Changed to multibuild (bsc#1151455).

Added support for using externally allocated memory in DPDK.

Added check for ensuring allocated memory is addressable by devices.

Updated the C11 memory model version of the ring library.

Added NXP CAAM JR PMD.

Added support for GEN3 devices to Intel QAT driver.

Added Distributed Software Eventdev PMD.

Updated KNI kernel module, rte_kni library, and KNI sample application.

Add a new sample application for vDPA.

Updated mlx5 driver.
 * Improved security of PMD to prevent the NIC from getting stuck when
 the application misbehaves.
 * Reworked flow engine to supported e-switch flow rules (transfer
 attribute).
 * Added support for header re-write(L2-L4), VXLAN encap/decap, count,
 match on TCP flags and multiple flow groups with e-switch flow rules.
 * Added support for match on metadata, VXLAN and MPLS encap/decap with
 flow rules.
 * Added support for RTE_ETH_DEV_CLOSE_REMOVE flag to provide better
 support for representors.
 * Added support for meson build.
 * Fixed build issue with PPC.
 * Added support for BlueField VF.
 * Added support for externally allocated static memory for DMA.");

  script_tag(name:"affected", value:"'dpdk' package(s) on SUSE Linux Enterprise Module for Server Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debuginfo", rpm:"dpdk-debuginfo~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debugsource", rpm:"dpdk-debugsource~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel-debuginfo", rpm:"dpdk-devel-debuginfo~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~18.11.3_k4.12.14_150.41~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default-debuginfo", rpm:"dpdk-kmp-default-debuginfo~18.11.3_k4.12.14_150.41~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx", rpm:"dpdk-thunderx~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-debuginfo", rpm:"dpdk-thunderx-debuginfo~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-debugsource", rpm:"dpdk-thunderx-debugsource~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel", rpm:"dpdk-thunderx-devel~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel-debuginfo", rpm:"dpdk-thunderx-devel-debuginfo~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default", rpm:"dpdk-thunderx-kmp-default~18.11.3_k4.12.14_150.41~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default-debuginfo", rpm:"dpdk-thunderx-kmp-default-debuginfo~18.11.3_k4.12.14_150.41~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools-debuginfo", rpm:"dpdk-tools-debuginfo~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-18_11", rpm:"libdpdk-18_11~18.11.3~3.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-18_11-debuginfo", rpm:"libdpdk-18_11-debuginfo~18.11.3~3.16.1", rls:"SLES15.0"))) {
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
