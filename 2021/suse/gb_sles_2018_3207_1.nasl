# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3207.1");
  script_cve_id("CVE-2014-9939", "CVE-2017-15938", "CVE-2017-15939", "CVE-2017-15996", "CVE-2017-16826", "CVE-2017-16827", "CVE-2017-16828", "CVE-2017-16829", "CVE-2017-16830", "CVE-2017-16831", "CVE-2017-16832", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8396", "CVE-2017-8421", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:12:00 +0000 (Wed, 22 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3207-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3207-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183207-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2018:3207-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils to 2.31 fixes the following issues:

These security issues were fixed:
CVE-2017-15996: readelf allowed remote attackers to cause a denial of
 service (excessive memory allocation) or possibly have unspecified other
 impact via a crafted ELF file that triggered a buffer overflow on fuzzed
 archive header (bsc#1065643).

CVE-2017-15939: Binary File Descriptor (BFD) library (aka libbfd)
 mishandled NULL files in a .debug_line file table, which allowed remote
 attackers to cause a denial of service (NULL pointer dereference and
 application crash) via a crafted ELF file, related to concat_filename
 (bsc#1065689).

CVE-2017-15938: the Binary File Descriptor (BFD) library (aka libbfd)
 miscalculated DW_FORM_ref_addr die refs in the case of a relocatable
 object file, which allowed remote attackers to cause a denial of service
 (find_abstract_instance_name invalid memory read, segmentation fault,
 and application crash) (bsc#1065693).

CVE-2017-16826: The coff_slurp_line_table function the Binary File
 Descriptor (BFD) library (aka libbfd) allowed remote attackers to cause
 a denial of service (invalid memory access and application crash) or
 possibly have unspecified other impact via a crafted PE file
 (bsc#1068640).

CVE-2017-16832: The pe_bfd_read_buildid function in the Binary File
 Descriptor (BFD) library (aka libbfd) did not validate size and offset
 values in the data dictionary, which allowed remote attackers to cause a
 denial of service (segmentation violation and application crash) or
 possibly have unspecified other impact via a crafted PE file
 (bsc#1068643).

CVE-2017-16831: Binary File Descriptor (BFD) library (aka libbfd) did
 not validate the symbol count, which allowed remote attackers to cause a
 denial of service (integer overflow and application crash, or excessive
 memory allocation) or possibly have unspecified other impact via a
 crafted PE file (bsc#1068887).

CVE-2017-16830: The print_gnu_property_note function did not have
 integer-overflow protection on 32-bit platforms, which allowed remote
 attackers to cause a denial of service (segmentation violation and
 application crash) or possibly have unspecified other impact via a
 crafted ELF file (bsc#1068888).

CVE-2017-16829: The _bfd_elf_parse_gnu_properties function in the Binary
 File Descriptor (BFD) library (aka libbfd) did not prevent negative
 pointers, which allowed remote attackers to cause a denial of service
 (out-of-bounds read and application crash) or possibly have unspecified
 other impact via a crafted ELF file (bsc#1068950).

CVE-2017-16828: The display_debug_frames function allowed remote
 attackers to cause a denial of service (integer overflow and heap-based
 buffer over-read, and application crash) or possibly have unspecified
 other impact via a crafted ELF file (bsc#1069176).

CVE-2017-16827: The aout_get_external_symbols function in the Binary
 File ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE OpenStack Cloud 7.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31~9.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.31~9.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.31~9.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31~9.26.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.31~9.26.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.31~9.26.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31~9.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.31~9.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.31~9.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31~9.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.31~9.26.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.31~9.26.1", rls:"SLES12.0SP3"))) {
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
