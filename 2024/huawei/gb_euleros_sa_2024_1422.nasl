# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1422");
  script_cve_id("CVE-2023-46246", "CVE-2023-4733", "CVE-2023-4734", "CVE-2023-4735", "CVE-2023-4738", "CVE-2023-4750", "CVE-2023-4751", "CVE-2023-4752", "CVE-2023-4781", "CVE-2023-48231", "CVE-2023-48233", "CVE-2023-48234", "CVE-2023-48235", "CVE-2023-48236", "CVE-2023-48237", "CVE-2023-48706", "CVE-2023-5344", "CVE-2023-5441", "CVE-2023-5535");
  script_tag(name:"creation_date", value:"2024-03-21 04:24:36 +0000 (Thu, 21 Mar 2024)");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 14:16:54 +0000 (Mon, 16 Oct 2023)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2024-1422)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1422");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1422");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2024-1422 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use After Free in GitHub repository vim/vim prior to v9.0.2010.(CVE-2023-5535)

NULL Pointer Dereference in GitHub repository vim/vim prior to 20d161ace307e28690229b68584f2d84556f8960.(CVE-2023-5441)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1969.(CVE-2023-5344)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1873.(CVE-2023-4781)

Use After Free in GitHub repository vim/vim prior to 9.0.1858.(CVE-2023-4752)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1331.(CVE-2023-4751)

Use After Free in GitHub repository vim/vim prior to 9.0.1857.(CVE-2023-4750)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1848.(CVE-2023-4738)

Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1847.(CVE-2023-4735)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.1846.(CVE-2023-4734)

Use After Free in GitHub repository vim/vim prior to 9.0.1840.(CVE-2023-4733)

Vim is a UNIX editor that, prior to version 9.0.2121, has a heap-use-after-free vulnerability. When executing a `:s` command for the very first time and using a sub-replace-special atom inside the substitution part, it is possible that the recursive `:s` call causes free-ing of memory which may later then be accessed by the initial `:s` command. The user must intentionally execute the payload and the whole process is a bit tricky to do since it seems to work only reliably for the very first :s command. It may also cause a crash of Vim. Version 9.0.2121 contains a fix for this issue.(CVE-2023-48706)

Vim is an open source command line text editor. In affected versions when shifting lines in operator pending mode and using a very large value, it may be possible to overflow the size of integer. Impact is low, user interaction is required and a crash may not even happen in all situations. This issue has been addressed in commit `6bf131888` which has been included in version 9.0.2112. Users are advised to upgrade. There are no known workarounds for this vulnerability.(CVE-2023-48237)

Vim is an open source command line text editor. When using the z= command, the user may overflow the count with values larger than MAX_INT. Impact is low, user interaction is required and a crash may not even happen in all situations. This vulnerability has been addressed in commit `73b2d379` which has been included in release version 9.0.2111. Users are advised to upgrade. There are no known workarounds for this vulnerability.(CVE-2023-48236)

Vim is an open source command line text editor. When getting the count for a normal mode z command, it may overflow for large counts given. Impact is low, user interaction is required and a crash may not even happen in all situations. This issue has been addressed in commit `58f9befca1` which has been included in release version 9.0.2109. Users are advised to upgrade. There are no known ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization release 2.11.1.");

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

if(release == "EULEROSVIRT-2.11.1") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0~1.h25.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0~1.h25.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~9.0~1.h25.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0~1.h25.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
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
