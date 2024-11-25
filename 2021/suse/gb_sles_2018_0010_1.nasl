# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0010.1");
  script_cve_id("CVE-2017-17805", "CVE-2017-17806", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-08 23:37:32 +0000 (Mon, 08 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0010-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180010-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bugfixes.
This update adds mitigations for various side channel attacks against modern CPUs that could disclose content of otherwise unreadable memory
(bnc#1068032).
- CVE-2017-5753 / 'SpectreAttack': Local attackers on systems with modern
 CPUs featuring deep instruction pipelining could use attacker
 controllable speculative execution over code patterns in the Linux
 Kernel to leak content from
 otherwise not readable memory in the same address space, allowing
 retrieval of passwords, cryptographic keys and other secrets.
 This problem is mitigated by adding speculative fencing on affected code paths throughout the Linux kernel.
- CVE-2017-5715 / 'SpectreAttack': Local attackers on systems with modern
 CPUs featuring branch prediction could use mispredicted branches to
 speculatively execute code patterns that in turn could be made to leak
 other non-readable content in the same address space, an attack similar
 to CVE-2017-5753.
 This problem is mitigated by disabling predictive branches, depending
 on CPU architecture either by firmware updates and/or fixes in the
 user-kernel privilege boundaries.
 Please also check with your CPU / Hardware vendor for available firmware or BIOS updates.
 As this feature can have a performance impact, it can be disabled using the 'nospec' kernel commandline option.
- CVE-2017-5754 / 'MeltdownAttack': Local attackers on systems with modern
 CPUs featuring deep instruction pipelining could use code patterns in
 userspace to speculative executive code that would read
 otherwise read protected memory.
 This problem is mitigated by unmapping the Linux Kernel from the user address space during user code execution, following a approach called
'KAISER'. The terms used here are 'KAISER' / 'Kernel Address Isolation'
and 'PTI' / 'Page Table Isolation'.
 This is only enabled by default on affected architectures.
 This feature can be enabled / disabled by the 'pti=[on<pipe>off<pipe>auto]' or
'nopti' commandline options.
The following security bugs were fixed:
- CVE-2017-17806: The HMAC implementation (crypto/hmac.c) in the Linux
 kernel did not validate that the underlying cryptographic hash algorithm
 is unkeyed, allowing a local attacker able to use the AF_ALG-based hash
 interface (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3 hash algorithm
 (CONFIG_CRYPTO_SHA3) to cause a kernel stack buffer overflow by
 executing a crafted sequence of system calls that encounter a missing
 SHA-3 initialization (bnc#1073874).
- CVE-2017-17805: The Salsa20 encryption algorithm in the Linux kernel did
 not correctly handle zero-length inputs, allowing a local attacker able
 to use the AF_ALG-based skcipher interface
 (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of service
 (uninitialized-memory free and kernel crash) or have unspecified other
 impact by executing a crafted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Container as a Service Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.103~6.38.1", rls:"SLES12.0SP3"))) {
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
