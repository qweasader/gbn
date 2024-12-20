# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2258");
  script_cve_id("CVE-2020-19724", "CVE-2020-21490", "CVE-2021-46174", "CVE-2022-48064", "CVE-2022-48065", "CVE-2023-25588");
  script_tag(name:"creation_date", value:"2024-08-22 04:43:34 +0000 (Thu, 22 Aug 2024)");
  script_version("2024-08-22T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-22 05:05:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-25 19:40:48 +0000 (Fri, 25 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2024-2258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2258");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2258");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'binutils' package(s) announced via the EulerOS-SA-2024-2258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Field `the_bfd` of `asymbol` is uninitialized in function `bfd_mach_o_get_synthetic_symtab`.(CVE-2023-25588)

GNU Binutils before 2.40 was discovered to contain a memory leak vulnerability var the function find_abstract_instance in dwarf2.c.(CVE-2022-48065)

GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the function bfd_dwarf2_find_nearest_line_with_alt at dwarf2.c. The attacker could supply a crafted ELF file and cause a DNS attack.(CVE-2022-48064)

Heap-based Buffer Overflow in function bfd_getl32 in Binutils objdump 3.37.(CVE-2021-46174)

An issue was discovered in GNU Binutils 2.34. It is a memory leak when process microblaze-dis.c. This one will consume memory on each insn disassembled.(CVE-2020-21490)

A memory consumption issue in get_data function in binutils/nm.c in GNU nm before 2.34 allows attackers to cause a denial of service via crafted command.(CVE-2020-19724)");

  script_tag(name:"affected", value:"'binutils' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.27~28.base.1.h56", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
