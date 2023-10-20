# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2204");
  script_cve_id("CVE-2015-8538", "CVE-2016-5034", "CVE-2016-5036", "CVE-2016-5038", "CVE-2016-5039", "CVE-2016-5040", "CVE-2016-5042", "CVE-2016-5043");
  script_tag(name:"creation_date", value:"2020-01-23 12:38:46 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-01 19:04:00 +0000 (Tue, 01 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for libdwarf (EulerOS-SA-2019-2204)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2204");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2204");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libdwarf' package(s) announced via the EulerOS-SA-2019-2204 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"dwarf_leb.c in libdwarf allows attackers to cause a denial of service (SIGSEGV).(CVE-2015-8538)

The dwarf_dealloc function in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted DWARF section.(CVE-2016-5043)

The dwarf_get_aranges_list function in libdwarf before 20160923 allows remote attackers to cause a denial of service (infinite loop and crash) via a crafted DWARF section.(CVE-2016-5042)

libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a large length value in a compilation unit header.(CVE-2016-5040)

The get_attr_value function in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted object with all-bits on.(CVE-2016-5039)

The dwarf_get_macro_startend_file function in dwarf_macro5.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted string offset for .debug_str.(CVE-2016-5038)

The dump_block function in print_sections.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds read) via crafted frame data.(CVE-2016-5036)

dwarf_elf_access.c in libdwarf before 20160923 allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file, related to relocation records.(CVE-2016-5034)");

  script_tag(name:"affected", value:"'libdwarf' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libdwarf", rpm:"libdwarf~20180809~1.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
