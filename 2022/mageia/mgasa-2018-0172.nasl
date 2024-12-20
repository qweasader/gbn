# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0172");
  script_cve_id("CVE-2017-5715", "CVE-2017-5754", "CVE-2018-1065");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-22 14:13:47 +0000 (Thu, 22 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0172");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0172.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22703");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22704");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22731");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.21");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.22");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.23");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.24");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.25");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) announced via the MGASA-2018-0172 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on the upstream 4.14.25 and updates the
KPTI mitigation for Meltdown (CVE-2017-5754) on 32bit x86. It also adds
ome optimizations and improvements to mitigate some of the slowdons
caused by the Meltdown (CVE-2017-5754) and Spectre, variant 2
(CVE-2017-5715).

Other security fixes in this update:

The netfilter subsystem in the Linux kernel through 4.15.7 mishandles the
case of a rule blob that contains a jump but lacks a user-defined chain,
which allows local users to cause a denial of service (NULL pointer
dereference) by leveraging the CAP_NET_RAW or CAP_NET_ADMIN capability,
related to arpt_do_table in net/ipv4/netfilter/arp_tables.c, ipt_do_table
in net/ipv4/netfilter/ip_tables.c, and ip6t_do_table in
net/ipv6/netfilter/ip6_tables.c (CVE-2018-1065).

Other changes in this update:

WireGuard has been updated to 0.0.20180304.

A fix in the scsi subsystem that prevents the kernel to hang or oops,
triggered at least when trying to mount some raid6 setups (mga#22704).

input/goodix: add support for GDIX1002 (mga#22703)

For other upstream fixes in this update, read the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-4.14.25-1.mga6", rpm:"kernel-desktop-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-4.14.25-1.mga6", rpm:"kernel-desktop-armv6v7-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-devel-4.14.25-1.mga6", rpm:"kernel-desktop-armv6v7-devel-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-devel-latest", rpm:"kernel-desktop-armv6v7-devel-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-latest", rpm:"kernel-desktop-armv6v7-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-4.14.25-1.mga6", rpm:"kernel-desktop-devel-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-4.14.25-1.mga6", rpm:"kernel-desktop586-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-4.14.25-1.mga6", rpm:"kernel-desktop586-devel-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-4.14.25-1.mga6", rpm:"kernel-server-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-4.14.25-1.mga6", rpm:"kernel-server-devel-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-4.14.25-1.mga6", rpm:"kernel-source-4.14.25-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.13~25.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.14.25~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.25-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.25-desktop-1.mga6~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.25-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.25-desktop586-1.mga6~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.25-server-1.mga6", rpm:"vboxadditions-kernel-4.14.25-server-1.mga6~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.25-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.25-desktop-1.mga6~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.25-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.25-desktop586-1.mga6~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.25-server-1.mga6", rpm:"virtualbox-kernel-4.14.25-server-1.mga6~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.2.8~5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireguard-tools", rpm:"wireguard-tools~0.0.20180304~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.25-desktop-1.mga6", rpm:"xtables-addons-kernel-4.14.25-desktop-1.mga6~2.13~25.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.25-desktop586-1.mga6", rpm:"xtables-addons-kernel-4.14.25-desktop586-1.mga6~2.13~25.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.25-server-1.mga6", rpm:"xtables-addons-kernel-4.14.25-server-1.mga6~2.13~25.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.13~25.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.13~25.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.13~25.mga6", rls:"MAGEIA6"))) {
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
