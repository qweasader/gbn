# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0303");
  script_cve_id("CVE-2018-1000667", "CVE-2018-10016", "CVE-2018-10254", "CVE-2018-10316", "CVE-2018-16382", "CVE-2018-16517", "CVE-2018-16999", "CVE-2018-19214", "CVE-2018-19215");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-13 13:55:48 +0000 (Thu, 13 Dec 2018)");

  script_name("Mageia: Security Advisory (MGASA-2020-0303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0303");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0303.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26916");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-07/msg00015.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-July/007073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nasm' package(s) announced via the MGASA-2020-0303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Netwide Assembler (NASM) 2.13 has a stack-based buffer over-read in the disasm
function of the disasm/disasm.c file. Remote attackers could leverage this
vulnerability to cause a denial of service or possibly have unspecified other
impact via a crafted ELF file (CVE-2018-10254).

Netwide Assembler (NASM) 2.14rc0 has an endless while loop in the
assemble_file function of asm/nasm.c because of a globallineno integer
overflow (CVE-2018-10316).

Netwide Assembler (NASM) 2.14rc15 has a buffer over-read in x86/regflags.c
(CVE-2018-16382).

NASM nasm-2.13.03 nasm- 2.14rc15 version 2.14rc15 and earlier contains a
memory corruption (crashed) of nasm when handling a crafted file due to
function assemble_file(inname, depend_ptr) at asm/nasm.c:482. vulnerability in
function assemble_file(inname, depend_ptr) at asm/nasm.c:482. that can result
in aborting/crash nasm program. This attack appear to be exploitable via a
specially crafted asm file (CVE-2018-1000667).

asm/labels.c in Netwide Assembler (NASM) is prone to NULL Pointer Dereference,
which allows the attacker to cause a denial of service via a crafted file
(CVE-2018-16517).

Netwide Assembler (NASM) 2.14rc15 has an invalid memory write (segmentation
fault) in expand_smacro in preproc.c, which allows attackers to cause a denial
of service via a crafted input file (CVE-2018-16999).

Netwide Assembler (NASM) 2.14rc16 has a heap-based buffer over-read in
expand_mmac_params in asm/preproc.c for the special cases of the % and $ and !
characters (CVE-2018-19215).

Netwide Assembler (NASM) 2.14rc15 has a heap-based buffer over-read in
expand_mmac_params in asm/preproc.c for insufficient input (CVE-2018-19214).");

  script_tag(name:"affected", value:"'nasm' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"nasm", rpm:"nasm~2.14.02~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-doc", rpm:"nasm-doc~2.14.02~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-rdoff", rpm:"nasm-rdoff~2.14.02~1.mga7", rls:"MAGEIA7"))) {
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
