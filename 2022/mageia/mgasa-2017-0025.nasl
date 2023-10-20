# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0025");
  script_cve_id("CVE-2016-7382", "CVE-2016-7389", "CVE-2016-8826");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:38:00 +0000 (Mon, 28 Nov 2016)");

  script_name("Mageia: Security Advisory (MGASA-2017-0025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0025");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0025.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19994");
  script_xref(name:"URL", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4246");
  script_xref(name:"URL", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4278");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldetect-lst, nvidia-current' package(s) announced via the MGASA-2017-0025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This proprietary nvidia-current driver update provides an upgrade to the
new R375 long lived branch adding support for nVidia Geforce 10
(GTX10xx, Pascal) series hardware and fixes the following security
issues:

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer (nvidia.ko) handler where a missing permissions check may allow
users to gain access to arbitrary physical memory, leading to an
escalation of privileges (CVE-2016-7382).

NVIDIA GPU Display Driver on Linux contains a vulnerability in the
kernel mode layer (nvidia.ko) handler for mmap() where improper input
validation may allow users to gain access to arbitrary physical memory,
leading to an escalation of privileges (CVE-2016-7389).

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer (nvidia.ko) where a user can cause a GPU interrupt storm, leading
to a denial of service (CVE-2016-8826).");

  script_tag(name:"affected", value:"'ldetect-lst, nvidia-current' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia-current", rpm:"dkms-nvidia-current~375.26~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldetect-lst", rpm:"ldetect-lst~0.1.346.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldetect-lst-devel", rpm:"ldetect-lst-devel~0.1.346.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current", rpm:"nvidia-current~375.26~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-cuda-opencl", rpm:"nvidia-current-cuda-opencl~375.26~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-devel", rpm:"nvidia-current-devel~375.26~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-doc-html", rpm:"nvidia-current-doc-html~375.26~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia-current", rpm:"x11-driver-video-nvidia-current~375.26~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
