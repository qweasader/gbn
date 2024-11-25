# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856404");
  script_version("2024-09-12T07:59:53+0000");
  script_cve_id("CVE-2023-31315");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-04 04:00:25 +0000 (Wed, 04 Sep 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:3081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3081-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UVFIGJW5H5BKAEJ6XVMB4LTSOJCYNPV3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:3081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

  * CVE-2023-31315: Fixed validation in a model specific register (MSR) that
      lead to modification of SMM configuration by malicious program with ring0
      access (bsc#1229069)

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20230724", rpm:"kernel-firmware-liquidio-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20230724", rpm:"kernel-firmware-nfp-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20230724", rpm:"kernel-firmware-brcm-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20230724", rpm:"kernel-firmware-mwifiex-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20230724", rpm:"kernel-firmware-chelsio-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20230724", rpm:"kernel-firmware-intel-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20230724", rpm:"kernel-firmware-ueagle-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20230724", rpm:"kernel-firmware-bluetooth-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20230724", rpm:"kernel-firmware-bnx2-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20230724", rpm:"kernel-firmware-sound-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20230724", rpm:"kernel-firmware-ath11k-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20230724", rpm:"kernel-firmware-mellanox-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20230724", rpm:"kernel-firmware-network-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20230724", rpm:"kernel-firmware-iwlwifi-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20230724", rpm:"kernel-firmware-atheros-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20230724", rpm:"kernel-firmware-mediatek-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-20230724", rpm:"kernel-firmware-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20230724", rpm:"kernel-firmware-ti-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20230724", rpm:"kernel-firmware-i915-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20230724", rpm:"kernel-firmware-media-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20230724", rpm:"kernel-firmware-ath10k-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20230724", rpm:"kernel-firmware-qcom-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20230724", rpm:"kernel-firmware-marvell-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20230724", rpm:"kernel-firmware-qlogic-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20230724", rpm:"kernel-firmware-platform-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20230724", rpm:"kernel-firmware-prestera-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20230724", rpm:"kernel-firmware-dpaa2-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20230724", rpm:"kernel-firmware-realtek-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20230724", rpm:"kernel-firmware-usb-network-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20230724", rpm:"kernel-firmware-all-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20230724", rpm:"ucode-amd-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20230724", rpm:"kernel-firmware-radeon-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20230724", rpm:"kernel-firmware-serial-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20230724", rpm:"kernel-firmware-nvidia-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20230724", rpm:"kernel-firmware-amdgpu-20230724~150500.3.12.1", rls:"openSUSELeap15.5"))) {
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