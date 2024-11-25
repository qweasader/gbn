# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1398");
  script_cve_id("CVE-2014-9482", "CVE-2016-5028", "CVE-2016-5029", "CVE-2016-5030", "CVE-2016-5031", "CVE-2016-5032", "CVE-2016-5033", "CVE-2016-5034", "CVE-2016-5035", "CVE-2016-5036", "CVE-2016-5037", "CVE-2016-5038", "CVE-2016-5039", "CVE-2016-5040", "CVE-2016-5041", "CVE-2016-5042", "CVE-2016-5043", "CVE-2016-5044", "CVE-2016-7510", "CVE-2016-8679", "CVE-2016-8680", "CVE-2016-8681");
  script_tag(name:"creation_date", value:"2020-04-16 05:50:17 +0000 (Thu, 16 Apr 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-22 17:49:16 +0000 (Wed, 22 Feb 2017)");

  script_name("Huawei EulerOS: Security Advisory for libdwarf (EulerOS-SA-2020-1398)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1398");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1398");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libdwarf' package(s) announced via the EulerOS-SA-2020-1398 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free vulnerability in dwarfdump in libdwarf 20130126 through 20140805 might allow remote attackers to cause a denial of service (program crash) via a crafted ELF file.(CVE-2014-9482)

The print_frame_inst_bytes function in libdwarf before 20160923 allows remote attackers to cause a denial of service (NULL pointer dereference) via an object file with empty bss-like sections.(CVE-2016-5028)

The create_fullest_file_path function in libdwarf before 20160923 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted dwarf file.(CVE-2016-5029)

The _dwarf_calculate_info_section_end_ptr function in libdwarf before 20160923 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted file.(CVE-2016-5030)

The print_frame_inst_bytes function in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted file.(CVE-2016-5031)

The dwarf_get_xu_hash_entry function in libdwarf before 20160923 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2016-5032)

The print_exprloc_content function in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted file.(CVE-2016-5033)

dwarf_elf_access.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file, related to relocation records.(CVE-2016-5034)

The _dwarf_read_line_table_header function in dwarf_line_table_reader.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted file.(CVE-2016-5035)

The dump_block function in print_sections.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via crafted frame data.(CVE-2016-5036)

The _dwarf_load_section function in libdwarf before 20160923 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted file.(CVE-2016-5037)

The dwarf_get_macro_startend_file function in dwarf_macro5.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted string offset for .debug_str.(CVE-2016-5038)

The get_attr_value function in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted object with all-bits on.(CVE-2016-5039)

libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a large length value in a compilation unit header.(CVE-2016-5040)

dwarf_macro5.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (NULL pointer dereference) via a debugging information entry using DWARF5 and without a DW_AT_name.(CVE-2016-5041)

The dwarf_get_aranges_list function in libdwarf before 20160923 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libdwarf' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libdwarf", rpm:"libdwarf~20170416~1", rls:"EULEROS-2.0SP3"))) {
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
