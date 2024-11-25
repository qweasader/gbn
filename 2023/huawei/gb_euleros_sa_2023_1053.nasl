# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1053");
  script_cve_id("CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4192", "CVE-2021-4193", "CVE-2022-0213", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0729");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-02 02:36:07 +0000 (Wed, 02 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2023-1053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1053");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-1053");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2023-1053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vim is vulnerable to Use After Free(CVE-2021-3796)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3778)

An out-of-bounds write flaw was found in vim's drawscreen.c win_redr_status() function. This flaw allows an attacker to trick a user to open a crafted file with specific arguments in vim, triggering an out-of-bounds write. The highest threat from this vulnerability is to confidentiality, integrity, and system availability.(CVE-2021-3872)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3928)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3927)

vim is vulnerable to Use After Free(CVE-2021-3974)

vim is vulnerable to Use After Free(CVE-2021-4069)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-4019)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2021-3984)

vim is vulnerable to Out-of-bounds Read(CVE-2021-4193)

vim is vulnerable to Use After Free(CVE-2021-4192)

vim is vulnerable to Heap-based Buffer Overflow(CVE-2022-0213)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0359)

Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.(CVE-2022-0351)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440.(CVE-2022-0729)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization 3.0.2.6.");

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

if(release == "EULEROSVIRT-3.0.2.6") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.4.160~4.h20.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.4.160~4.h20.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~7.4.160~4.h20.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.4.160~4.h20.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.6"))) {
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
