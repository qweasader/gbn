# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0770.1");
  script_cve_id("CVE-2022-42265", "CVE-2024-0074", "CVE-2024-0075");
  script_tag(name:"creation_date", value:"2024-03-06 04:22:02 +0000 (Wed, 06 Mar 2024)");
  script_version("2024-03-06T05:05:53+0000");
  script_tag(name:"last_modification", value:"2024-03-06 05:05:53 +0000 (Wed, 06 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-12 16:54:32 +0000 (Thu, 12 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0770-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240770-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed' package(s) announced via the SUSE-SU-2024:0770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed fixes the following issues:
Update to 550.54.14

Added vGPU Host and vGPU Guest support. For vGPU Host, please
 refer to the README.vgpu packaged in the vGPU Host Package for
 more details.

Security issues fixed:

CVE-2024-0074: A user could trigger a NULL ptr dereference.
CVE-2024-0075: A user could overwrite the end of a buffer, leading to crashes or code execution.

CVE-2022-42265: A unprivileged user could trigger an integer overflow which could lead to crashes or code execution.


create /run/udev/static_node-tags/uaccess/nvidia${devid} symlinks
 also during modprobing the nvidia module, this changes the issue
 of not having access to /dev/nvidia${devid}, when gfxcard has
 been replaced by a different gfx card after installing the driver


provide nvidia-open-driver-G06-kmp (jsc#PED-7117)

this makes it easy to replace the package from nVidia's
 CUDA repository with this presigned package");

  script_tag(name:"affected", value:"'kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06", rpm:"kernel-firmware-nvidia-gspx-G06~550.54.14~150400.9.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~550.54.14~150400.9.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-debugsource", rpm:"nvidia-open-driver-G06-signed-debugsource~550.54.14~150400.9.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~550.54.14~150400.9.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-default-debuginfo~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"SLES15.0SP4"))) {
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
