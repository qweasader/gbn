# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0372");
  script_cve_id("CVE-2016-7039", "CVE-2016-7097", "CVE-2016-8658", "CVE-2016-8666");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-17 22:48:29 +0000 (Mon, 17 Oct 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0372)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0372");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0372.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2016-0347.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19707");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19725");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.27");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.28");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.29");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.30");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2016-0372 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on the upstream 4.4.30 kernel and fixes at least
these security issues:

The filesystem implementation in the Linux kernel through 4.8.2
preserves the setgid bit during a setxattr call, which allows local
users to gain group privileges by leveraging the existence of a setgid
program with restrictions on execute permissions (CVE-2016-7097).

Stack-based buffer overflow in the brcmf_cfg80211_start_ap function in
drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux
kernel before 4.7.5 allows local users to cause a denial of service
(system crash) or possibly have unspecified other impact via a long SSID
Information Element in a command to a Netlink socket (CVE-2016-8658).

The IP stack in the Linux kernel before 4.6 allows remote attackers to
cause a denial of service (stack consumption and panic) or possibly have
unspecified other impact by triggering use of the GRO path for packets
with tunnel stacking, as demonstrated by interleaved IPv4 headers and
GRE headers, a related issue to CVE-2016-7039 (CVE-2016-8666).

The fix for CVE-2016-7039 added in MGASA-2016-0347 has been updated to
the final version merged upstream.

This update also resolves a regression where amdgpu and radeon users
would not get any display when using displayport (upstream regression
introduced in 4.4.21, mga#19707)

For other upstream fixes in this update, read the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-4.4.30-2.mga5", rpm:"kernel-desktop-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-4.4.30-2.mga5", rpm:"kernel-desktop-devel-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-4.4.30-2.mga5", rpm:"kernel-desktop586-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-4.4.30-2.mga5", rpm:"kernel-desktop586-devel-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-4.4.30-2.mga5", rpm:"kernel-server-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-4.4.30-2.mga5", rpm:"kernel-server-devel-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-4.4.30-2.mga5", rpm:"kernel-source-4.4.30-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.10~15.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.4.30~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.30-desktop-2.mga5", rpm:"vboxadditions-kernel-4.4.30-desktop-2.mga5~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.30-desktop586-2.mga5", rpm:"vboxadditions-kernel-4.4.30-desktop586-2.mga5~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.30-server-2.mga5", rpm:"vboxadditions-kernel-4.4.30-server-2.mga5~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.30-desktop-2.mga5", rpm:"virtualbox-kernel-4.4.30-desktop-2.mga5~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.30-desktop586-2.mga5", rpm:"virtualbox-kernel-4.4.30-desktop586-2.mga5~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.30-server-2.mga5", rpm:"virtualbox-kernel-4.4.30-server-2.mga5~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.1.2~10.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.4.30-desktop-2.mga5", rpm:"xtables-addons-kernel-4.4.30-desktop-2.mga5~2.10~15.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.4.30-desktop586-2.mga5", rpm:"xtables-addons-kernel-4.4.30-desktop586-2.mga5~2.10~15.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.4.30-server-2.mga5", rpm:"xtables-addons-kernel-4.4.30-server-2.mga5~2.10~15.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.10~15.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.10~15.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.10~15.mga5", rls:"MAGEIA5"))) {
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
