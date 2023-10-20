# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0443");
  script_cve_id("CVE-2022-2602", "CVE-2022-3524", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3543", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3594", "CVE-2022-3619", "CVE-2022-3623", "CVE-2022-3628", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-43945");
  script_tag(name:"creation_date", value:"2022-11-28 04:13:48 +0000 (Mon, 28 Nov 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:00 +0000 (Mon, 28 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0443)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0443");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0443.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31150");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.75");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.76");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.77");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.78");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.79");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0443 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.79 and fixes at least the
following security issues:

A flaw was found in the Linux kernel. A race issue occurs between an
io_uring request and the Unix socket garbage collector, allowing an attacker
local privilege escalation (CVE-2022-2602).

A vulnerability was found in Linux Kernel. It has been declared as
problematic. Affected by this vulnerability is the function
ipv6_renew_options of the component IPv6 Handler. The manipulation leads
to memory leak. The attack can be launched remotely (CVE-2022-3524).

A vulnerability classified as problematic was found in Linux Kernel.
Affected by this vulnerability is the function mvpp2_dbgfs_port_init of
the file drivers/net/ethernet/marvell/mvpp2/mvpp2_debugfs.c of the
component mvpp2. The manipulation leads to memory leak (CVE-2022-3535).

A vulnerability classified as problematic was found in Linux Kernel. This
vulnerability affects the function bnx2x_tpa_stop of the file drivers/net/
ethernet/broadcom/bnx2x/bnx2x_cmn.c of the component BPF. The manipulation
leads to memory leak (CVE-2022-3542).

A vulnerability, which was classified as problematic, has been found in
Linux Kernel. This issue affects the function unix_sock_destructor/
unix_release_sock of the file net/unix/af_unix.c of the component BPF.
The manipulation leads to memory leak (CVE-2022-3543).

A vulnerability classified as critical was found in Linux Kernel. Affected
by this vulnerability is the function l2cap_reassemble_sdu of the file
net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation
leads to use after free (CVE-2022-3564).

A vulnerability, which was classified as critical, has been found in Linux
Kernel. Affected by this issue is the function del_timer of the file
drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The manipulation
leads to use after free (CVE-2022-3565).

A vulnerability was found in Linux Kernel. It has been declared as
problematic. Affected by this vulnerability is the function intr_callback
of the file drivers/net/usb/r8152.c of the component BPF. The manipulation
leads to logging of excessive data. The attack can be launched remotely
(CVE-2022-3594).

A vulnerability has been found in Linux Kernel and classified as
problematic. This vulnerability affects the function l2cap_recv_acldata
of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
manipulation leads to memory leak (CVE-2022-3619).

A vulnerability was found in Linux Kernel. It has been declared as
problematic. Affected by this vulnerability is the function follow_page_pte
of the file mm/gup.c of the component BPF. The manipulation leads to race
condition (CVE-2022-3623).

An intra-object buffer overflow was found in brcmfmac, which can be
triggered by a malicious USB causing a Denial-of-Service (CVE-2022-3628).

drivers/video/fbdev/smscufx.c in the Linux kernel through 5.19.12 has ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.79-1.mga8", rpm:"kernel-linus-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.79-1.mga8", rpm:"kernel-linus-devel-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.79-1.mga8", rpm:"kernel-linus-source-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
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
