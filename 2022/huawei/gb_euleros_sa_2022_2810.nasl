# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2810");
  script_cve_id("CVE-2022-2125", "CVE-2022-2923", "CVE-2022-2980", "CVE-2022-3234", "CVE-2022-3235", "CVE-2022-3256", "CVE-2022-3296", "CVE-2022-3297", "CVE-2022-3324", "CVE-2022-3352");
  script_tag(name:"creation_date", value:"2022-12-09 04:14:25 +0000 (Fri, 09 Dec 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 23:35:00 +0000 (Fri, 30 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-2810)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2810");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-2810");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-2810 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use After Free in GitHub repository vim/vim prior to 9.0.0530.(CVE-2022-3256)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483.(CVE-2022-3234)

Use After Free in GitHub repository vim/vim prior to 9.0.0579.(CVE-2022-3297)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598.(CVE-2022-3324)

Use After Free in GitHub repository vim/vim prior to 9.0.0614.(CVE-2022-3352)

Use After Free in GitHub repository vim/vim prior to 9.0.0490.(CVE-2022-3235)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577.(CVE-2022-3296)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0259.(CVE-2022-2980)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240.(CVE-2022-2923)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2125)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~8.1.450~1.h41.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.1.450~1.h41.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.1.450~1.h41.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.1.450~1.h41.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.1.450~1.h41.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
