# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0286");
  script_tag(name:"creation_date", value:"2022-08-19 04:45:01 +0000 (Fri, 19 Aug 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0286");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0286.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30723");
  script_xref(name:"URL", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5383");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia390' package(s) announced via the MGASA-2022-0286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nvidia390 packages fix security vulnerabilities:

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel
mode layer (nvidia.ko), where a local user with basic capabilities can cause
improper input validation, which may lead to denial of service, escalation
of privileges, data tampering, and limited information disclosure
(CVE-2022-31607).

NVIDIA GPU Display Driver for Linux contains a vulnerability in an optional
D-Bus configuration file, where a local user with basic capabilities can
impact protected D-Bus endpoints, which may lead to code execution, denial
of service, escalation of privileges, information disclosure, and data
tampering (CVE-2022-31608).

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel
mode layer, where a local user with basic capabilities can cause a null-
pointer dereference, which may lead to denial of service (CVE-2022-31615).

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel
mode layer, where a local user with basic capabilities can cause a null-
pointer dereference, which may lead to denial of service (CVE-2022-34665).

NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability
in the kernel mode layer, where a local user with basic capabilities can
cause a null-pointer dereference, which may lead to denial of service
(CVE-2022-34666).");

  script_tag(name:"affected", value:"'nvidia390' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia390", rpm:"dkms-nvidia390~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390", rpm:"nvidia390~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-cuda-opencl", rpm:"nvidia390-cuda-opencl~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-devel", rpm:"nvidia390-devel~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-doc-html", rpm:"nvidia390-doc-html~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-lib32", rpm:"nvidia390-lib32~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-utils", rpm:"nvidia390-utils~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia390", rpm:"x11-driver-video-nvidia390~390.154~1.mga8.nonfree", rls:"MAGEIA8"))) {
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
