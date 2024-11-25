# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0251");
  script_cve_id("CVE-2022-40982", "CVE-2023-1206", "CVE-2023-20569", "CVE-2023-34319", "CVE-2023-4004", "CVE-2023-4147");
  script_tag(name:"creation_date", value:"2023-08-24 04:11:47 +0000 (Thu, 24 Aug 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 14:27:55 +0000 (Tue, 15 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0251");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0251.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32169");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.123");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.124");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.125");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.126");
  script_xref(name:"URL", value:"https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7005.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00828.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-432.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kerne-linusl update is based on upstream 5.15.126 and fixes or
adds mitigations for at least the following security issues:

Information exposure through microarchitectural state after transient
execution in certain vector execution units for some Intel(R) Processors
may allow an authenticated user to potentially enable information disclosure
via local access (CVE-2022-40982, INTEL-SA-00828).

A hash collision flaw was found in the IPv6 connection lookup table in
the Linux kernel's IPv6 functionality when a user makes a new kind of SYN
flood attack. A user located in the local network or with a high bandwidth
connection can increase the CPU usage of the server that accepts IPV6
connections up to 95% (CVE-2023-1206).

A use-after-free flaw was found in the Linux kernel's netfilter in the
way a user triggers the nft_pipapo_remove function with the element,
without a NFT_SET_EXT_KEY_END. This issue could allow a local user to
crash the system or potentially escalate their privileges on the system
(CVE-2023-4004).

A use-after-free flaw was found in the Linux kernel's Netfilter
functionality when adding a rule with NFTA_RULE_CHAIN_ID. This flaw
allows a local user to crash or escalate their privileges on the system
(CVE-2023-4147).

A side channel vulnerability in some of the AMD CPUs may allow an attacker
to influence the return address prediction. This may result in speculative
execution at an attacker-controlled instruction pointer register,
potentially leading to information disclosure (CVE-2023-20569).

A buffer overrun vulnerability was found in the netback driver in Xen due
to an unusual split packet. This flaw allows an unprivileged guest to cause
a denial of service (DoS) of the host by sending network packets to the
backend, causing the backend to crash (CVE-2023-34319, XSA-432).

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.126-1.mga8", rpm:"kernel-linus-5.15.126-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.126~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.126-1.mga8", rpm:"kernel-linus-devel-5.15.126-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.126~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.126~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.126~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.126-1.mga8", rpm:"kernel-linus-source-5.15.126-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.126~1.mga8", rls:"MAGEIA8"))) {
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
