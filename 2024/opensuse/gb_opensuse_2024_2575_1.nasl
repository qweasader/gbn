# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856315");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2023-38417", "CVE-2023-47210");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:25 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:2575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2575-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QO4ZKJFET2VLARC6HMSN3B2FGOSOOLE3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:2575-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

  * CVE-2023-38417: Fixed improper input validation for some Intel(R)
      PROSet/Wireless WiFi software for linux before version 23.20 (bsc#1225600)

  * CVE-2023-47210: Fixed improper input validation for some Intel(R)
      PROSet/Wireless WiFi software before version 23.20 (bsc#1225601)

  * Update to version 20240712 (git commit ed874ed83cac):

  * amdgpu: update DMCUB to v0.0.225.0 for Various AMDGPU Asics

  * qcom: add gpu firmwares for x1e80100 chipset (bsc#1219458)

  * linux-firmware: add firmware for qat_402xx devices

  * amdgpu: update raven firmware

  * amdgpu: update SMU 13.0.10 firmware

  * amdgpu: update SDMA 6.0.3 firmware

  * amdgpu: update PSP 13.0.10 firmware

  * amdgpu: update GC 11.0.3 firmware

  * amdgpu: update vega20 firmware

  * amdgpu: update PSP 13.0.5 firmware

  * amdgpu: update PSP 13.0.8 firmware

  * amdgpu: update vega12 firmware

  * amdgpu: update vega10 firmware

  * amdgpu: update VCN 4.0.0 firmware

  * amdgpu: update SDMA 6.0.0 firmware

  * amdgpu: update PSP 13.0.0 firmware

  * amdgpu: update GC 11.0.0 firmware

  * amdgpu: update picasso firmware

  * amdgpu: update beige goby firmware

  * amdgpu: update vangogh firmware

  * amdgpu: update dimgrey cavefish firmware

  * amdgpu: update navy flounder firmware

  * amdgpu: update PSP 13.0.11 firmware

  * amdgpu: update GC 11.0.4 firmware

  * amdgpu: update green sardine firmware

  * amdgpu: update VCN 4.0.2 firmware

  * amdgpu: update SDMA 6.0.1 firmware

  * amdgpu: update PSP 13.0.4 firmware

  * amdgpu: update GC 11.0.1 firmware

  * amdgpu: update sienna cichlid firmware

  * amdgpu: update VPE 6.1.1 firmware

  * amdgpu: update VCN 4.0.6 firmware

  * amdgpu: update SDMA 6.1.1 firmware

  * amdgpu: update PSP 14.0.1 firmware

  * amdgpu: update GC 11.5.1 firmware

  * amdgpu: update VCN 4.0.5 firmware

  * amdgpu: update SDMA 6.1.0 firmware

  * amdgpu: update PSP 14.0.0 firmware

  * amdgpu: update GC 11.5.0 firmware

  * amdgpu: update navi14 firmware

  * amdgpu: update renoir firmware

  * amdgpu: update navi12 firmware

  * amdgpu: update PSP 13.0.6 firmware

  * amdgpu: update GC 9.4.3 firmware

  * amdgpu: update yellow carp firmware

  * amdgpu: update VCN 4.0.4 firmware

  * amdgpu: update SMU 13.0.7 firmware

  * amdgpu: update SDMA 6.0.2 firmware

  * amdgpu: update PSP 13.0.7 firmware

  * amdgpu: update GC 11.0.2 firmware

  * amdgpu: update navi10 firmware

  * amdgpu: update raven2 firmware

  * amdgpu: update aldebaran firmware

  * linux-f ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath12k-20240712", rpm:"kernel-firmware-ath12k-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20240712", rpm:"kernel-firmware-marvell-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20240712", rpm:"kernel-firmware-nfp-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20240712", rpm:"kernel-firmware-dpaa2-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20240712", rpm:"kernel-firmware-chelsio-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20240712", rpm:"kernel-firmware-prestera-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20240712", rpm:"kernel-firmware-realtek-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20240712", rpm:"kernel-firmware-bnx2-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20240712", rpm:"kernel-firmware-bluetooth-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20240712", rpm:"kernel-firmware-mellanox-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20240712", rpm:"kernel-firmware-liquidio-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20240712", rpm:"kernel-firmware-ath10k-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20240712", rpm:"ucode-amd-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20240712", rpm:"kernel-firmware-ueagle-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20240712", rpm:"kernel-firmware-mediatek-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20240712", rpm:"kernel-firmware-mwifiex-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20240712", rpm:"kernel-firmware-atheros-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20240712", rpm:"kernel-firmware-qcom-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20240712", rpm:"kernel-firmware-network-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20240712", rpm:"kernel-firmware-radeon-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20240712", rpm:"kernel-firmware-i915-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20240712", rpm:"kernel-firmware-iwlwifi-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20240712", rpm:"kernel-firmware-serial-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20240712", rpm:"kernel-firmware-usb-network-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20240712", rpm:"kernel-firmware-amdgpu-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20240712", rpm:"kernel-firmware-nvidia-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20240712", rpm:"kernel-firmware-intel-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20240712", rpm:"kernel-firmware-ti-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20240712", rpm:"kernel-firmware-ath11k-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20240712", rpm:"kernel-firmware-media-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20240712", rpm:"kernel-firmware-qlogic-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20240712", rpm:"kernel-firmware-all-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-20240712", rpm:"kernel-firmware-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20240712", rpm:"kernel-firmware-sound-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20240712", rpm:"kernel-firmware-platform-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20240712", rpm:"kernel-firmware-brcm-20240712~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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
