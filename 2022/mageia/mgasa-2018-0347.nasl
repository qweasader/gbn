# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0347");
  script_cve_id("CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-17 16:42:46 +0000 (Fri, 17 Aug 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0347");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0347.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23457");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23460");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.63");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.64");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.65");
  script_xref(name:"URL", value:"https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00161.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2018-0347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on the upstream 4.14.65 and adds fixes
and mitigations for the now publicly known security issue affecting
Intel processors called L1 Terminal Fault (L1TF):

Systems with microprocessors utilizing speculative execution and Intel
Software Guard Extensions (Intel SGX) may allow unauthorized disclosure
of information residing in the L1 data cache from an enclave to an
attacker with local user access via side-channel analysis (CVE-2018-3615).

Systems with microprocessors utilizing speculative execution and address
translations may allow unauthorized disclosure of information residing in
the L1 data cache to an attacker with local user access via a terminal
page fault and side-channel analysis (CVE-2018-3620).

Systems with microprocessors utilizing speculative execution and address
translations may allow unauthorized disclosure of information residing in
the L1 data cache to an attacker with local user access with guest OS
privilege via a terminal page fault and side-channel analysis
(CVE-2018-3646).

The impact of the L1TF security issues:
* Malicious applications may be able to infer the values of data in the
 operating system memory, or data from other applications.
* A malicious guest virtual machine (VM) may be able to infer the values
 of data in the VMM's memory, or values of data in the memory of other
 guest VMs.
* Malicious software running outside of SMM may be able to infer values
 of data in SMM memory.
* Malicious software running outside of an Intel(r) SGX enclave or within an
 enclave may be able to infer data from within another Intel SGX enclave.

NOTE! You also need to install the 0.20180807-1.mga6.nonfree microcode
update (mga#23457) or a bios update from your hardware vendor containing
the updated microcodes to get all current set of fixes and mitigations
for L1TF.

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.14.65-1.mga6", rpm:"kernel-linus-4.14.65-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.14.65~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.14.65-1.mga6", rpm:"kernel-linus-devel-4.14.65-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.14.65~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.14.65~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.14.65~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.14.65-1.mga6", rpm:"kernel-linus-source-4.14.65-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.14.65~1.mga6", rls:"MAGEIA6"))) {
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
