# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2129");
  script_cve_id("CVE-2017-12967", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14529", "CVE-2017-14930", "CVE-2017-14932", "CVE-2017-14934", "CVE-2017-14938", "CVE-2017-14939", "CVE-2017-14940", "CVE-2017-15021", "CVE-2017-15022", "CVE-2017-15025", "CVE-2017-15225", "CVE-2017-15938", "CVE-2017-15939", "CVE-2017-16832", "CVE-2017-17080", "CVE-2017-17121", "CVE-2017-17122", "CVE-2017-17123", "CVE-2017-17124", "CVE-2017-17125", "CVE-2017-7209", "CVE-2017-7299", "CVE-2017-8394", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9041", "CVE-2017-9745", "CVE-2017-9954", "CVE-2017-9955", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360");
  script_tag(name:"creation_date", value:"2020-01-23 12:35:23 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2019-2129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2129");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2129");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'binutils' package(s) announced via the EulerOS-SA-2019-2129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The dump_relocs_in_section function in objdump.c in GNU Binutils 2.29.1 does not check for reloc count integer overflows, which allows remote attackers to cause a denial of service (excessive memory allocation, or heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted PE file.(CVE-2017-17122)

The _bfd_coff_read_string_table function in coffgen.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1, does not properly validate the size of the external string table, which allows remote attackers to cause a denial of service (excessive memory consumption, or heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted COFF binary.(CVE-2017-17124)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1, allows remote attackers to cause a denial of service (memory access violation) or possibly have unspecified other impact via a COFF binary in which a relocation refers to a location after the end of the to-be-relocated section.(CVE-2017-17121)

nm.c and objdump.c in GNU Binutils 2.29.1 mishandle certain global symbols, which allows remote attackers to cause a denial of service (_bfd_elf_get_symbol_version_string buffer over-read and application crash) or possibly have unspecified other impact via a crafted ELF file.(CVE-2017-17125)

The _bfd_vms_slurp_etir function in bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, allows remote attackers to cause a denial of service (buffer overflow and application crash) or possibly have unspecified other impact via a crafted binary file, as demonstrated by mishandling of this file during 'objdump -D' execution.(CVE-2017-9745)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable to an invalid read of size 4 due to NULL pointer dereferencing of _bfd_elf_large_com_section. This vulnerability causes programs that conduct an analysis of binary programs using the libbfd library, such as objcopy, to crash.(CVE-2017-8394)

dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29, miscalculates DW_FORM_ref_addr die refs in the case of a relocatable object file, which allows remote attackers to cause a denial of service (find_abstract_instance_name invalid memory read, segmentation fault, and application crash).(CVE-2017-15938)

The pe_bfd_read_buildid function in peicode.h in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1, does not validate size and offset values in the data dictionary, which allows remote attackers to cause a denial of service (segmentation violation and application crash) or possibly have unspecified other impact via a crafted PE ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.27~28.base.1.h30.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.27~28.base.1.h30.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
