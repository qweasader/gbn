# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2369");
  script_cve_id("CVE-2022-0696", "CVE-2022-1154", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620", "CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1674", "CVE-2022-1720", "CVE-2022-1725", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1771", "CVE-2022-1785", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1927", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-2000", "CVE-2022-2042", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2175", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2257", "CVE-2022-2264", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2286", "CVE-2022-2287", "CVE-2022-2289", "CVE-2022-2304", "CVE-2022-2343", "CVE-2022-2344", "CVE-2022-2345", "CVE-2022-2522");
  script_tag(name:"creation_date", value:"2022-09-26 04:50:14 +0000 (Mon, 26 Sep 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 19:29:25 +0000 (Wed, 27 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-2369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2369");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-2369");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-2369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 in GitHub repository vim/vim prior to 8.2.4901. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 allows attackers to cause a denial of service (application crash) via a crafted input.(CVE-2022-1620)

Heap-based Buffer Overflow in function cmdline_erase_chars in GitHub repository vim/vim prior to 8.2.4899. These vulnerabilities are capable of crashing software, modify memory, and possible remote execution(CVE-2022-1619)

Use after free in append_command in GitHub repository vim/vim prior to 8.2.4895. This vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution(CVE-2022-1616)

Use after free in utf_ptr2char in GitHub repository vim/vim prior to 8.2.4646.(CVE-2022-1154)

Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution(CVE-2022-1621)

Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. These vulnerabilities are capable of crashing software, Modify Memory, and possible remote execution(CVE-2022-1629)

NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 in GitHub repository vim/vim prior to 8.2.4938. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 allows attackers to cause a denial of service (application crash) via a crafted input.(CVE-2022-1674)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4428.(CVE-2022-0696)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0060.(CVE-2022-2522)

Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2304)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045.(CVE-2022-2344)

Use After Free in GitHub repository vim/vim prior to 9.0.0046.(CVE-2022-2345)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044.(CVE-2022-2343)

Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.(CVE-2022-2285)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2284)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-2207)

NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.(CVE-2022-2208)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2287)

Use After Free in GitHub repository vim/vim prior to 9.0.(CVE-2022-2289)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2286)

Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.(CVE-2022-2257)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.(CVE-2022-2264)

Out-of-bounds Write in GitHub repository vim/vim prior to ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~8.2~1.h5.r34.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
