# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1208");
  script_cve_id("CVE-2022-2571", "CVE-2022-2598", "CVE-2022-2845", "CVE-2022-2923", "CVE-2022-2946", "CVE-2022-2980", "CVE-2022-3016", "CVE-2022-3099", "CVE-2022-3134", "CVE-2022-3234", "CVE-2022-3235", "CVE-2022-3256");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-23 18:42:00 +0000 (Fri, 23 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-1208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1208");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1208");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-1208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use After Free in GitHub repository vim/vim prior to 9.0.0530.(CVE-2022-3256)

Use After Free in GitHub repository vim/vim prior to 9.0.0490.(CVE-2022-3235)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483.(CVE-2022-3234)

Use After Free in GitHub repository vim/vim prior to 9.0.0389.(CVE-2022-3134)

Use After Free in GitHub repository vim/vim prior to 9.0.0360.(CVE-2022-3099)

Undefined Behavior for Input to API in GitHub repository vim/vim prior to 9.0.0100.(CVE-2022-2598)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0101.(CVE-2022-2571)

Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218.(CVE-2022-2845)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240.(CVE-2022-2923)

Use After Free in GitHub repository vim/vim prior to 9.0.0246.(CVE-2022-2946)

NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0259.(CVE-2022-2980)

Use After Free in GitHub repository vim/vim prior to 9.0.0286.(CVE-2022-3016)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2~1.h5.r41.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2~1.h5.r41.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.2~1.h5.r41.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2~1.h5.r41.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
