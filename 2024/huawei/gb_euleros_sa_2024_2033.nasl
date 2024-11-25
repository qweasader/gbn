# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2033");
  script_cve_id("CVE-2024-1048");
  script_tag(name:"creation_date", value:"2024-07-22 09:23:46 +0000 (Mon, 22 Jul 2024)");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 21:22:10 +0000 (Tue, 13 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2024-2033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2033");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2033");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2024-2033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the grub2-set-bootflag utility of grub2. After the fix of CVE-2019-14865, grub2-set-bootflag will create a temporary file with the new grubenv content and rename it to the original grubenv file. If the program is killed before the rename operation, the temporary file will not be removed and may fill the filesystem when invoked multiple times, resulting in a filesystem out of free inodes or blocks.(CVE-2024-1048)");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64", rpm:"grub2-efi-aa64~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-cdboot", rpm:"grub2-efi-aa64-cdboot~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-modules", rpm:"grub2-efi-aa64-modules~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.02~62.h42.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
