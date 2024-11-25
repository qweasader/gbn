# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1856");
  script_cve_id("CVE-2022-0319", "CVE-2022-0554", "CVE-2022-0572", "CVE-2022-0629", "CVE-2022-0685", "CVE-2022-0714", "CVE-2022-0729", "CVE-2022-0943");
  script_tag(name:"creation_date", value:"2022-06-16 04:26:03 +0000 (Thu, 16 Jun 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-02 02:36:07 +0000 (Wed, 02 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-1856)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1856");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1856");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-1856 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-based Buffer Overflow occurs in vim in GitHub repository vim/vim prior to 8.2.4563.(CVE-2022-0943)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4418.(CVE-2022-0685)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436.(CVE-2022-0714)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440.(CVE-2022-0729)

Out-of-bounds Read in vim/vim prior to 8.2.(CVE-2022-0319)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.(CVE-2022-0554)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0572)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0629)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2~1.h5.r18.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2~1.h5.r18.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.2~1.h5.r18.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2~1.h5.r18.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
