# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131197");
  script_cve_id("CVE-2016-0728");
  script_tag(name:"creation_date", value:"2016-01-25 05:27:45 +0000 (Mon, 25 Jan 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:40:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2016-0033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0033");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0033.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17557");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia304, kmod-nvidia340, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2016-0033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Perception Point Research Team found a reference leak in keyring in
join_session_keyring() that can be exploited to successfully escalate
privileges from a local user to root (CVE-2016-0728).

Other fixes in this kernel update:
- netfilter: nf_nat_redirect: add missing NULL pointer check");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia304, kmod-nvidia340, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-4.1.15-desktop-2.mga5", rpm:"broadcom-wl-kernel-4.1.15-desktop-2.mga5~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-4.1.15-desktop586-2.mga5", rpm:"broadcom-wl-kernel-4.1.15-desktop586-2.mga5~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-4.1.15-server-2.mga5", rpm:"broadcom-wl-kernel-4.1.15-server-2.mga5~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-4.1.15-desktop-2.mga5", rpm:"fglrx-kernel-4.1.15-desktop-2.mga5~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-4.1.15-desktop586-2.mga5", rpm:"fglrx-kernel-4.1.15-desktop586-2.mga5~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-4.1.15-server-2.mga5", rpm:"fglrx-kernel-4.1.15-server-2.mga5~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-4.1.15-2.mga5", rpm:"kernel-desktop-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-4.1.15-2.mga5", rpm:"kernel-desktop-devel-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-4.1.15-2.mga5", rpm:"kernel-desktop586-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-4.1.15-2.mga5", rpm:"kernel-desktop586-devel-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-4.1.15-2.mga5", rpm:"kernel-server-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-4.1.15-2.mga5", rpm:"kernel-server-devel-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-4.1.15-2.mga5", rpm:"kernel-source-4.1.15-2.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.271~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~15.200.1046~9.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia340", rpm:"kmod-nvidia340~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.7~8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-4.1.15-desktop-2.mga5", rpm:"nvidia-current-kernel-4.1.15-desktop-2.mga5~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-4.1.15-desktop586-2.mga5", rpm:"nvidia-current-kernel-4.1.15-desktop586-2.mga5~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-4.1.15-server-2.mga5", rpm:"nvidia-current-kernel-4.1.15-server-2.mga5~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~346.96~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-4.1.15-desktop-2.mga5", rpm:"nvidia304-kernel-4.1.15-desktop-2.mga5~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-4.1.15-desktop586-2.mga5", rpm:"nvidia304-kernel-4.1.15-desktop586-2.mga5~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-4.1.15-server-2.mga5", rpm:"nvidia304-kernel-4.1.15-server-2.mga5~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.128~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-kernel-4.1.15-desktop-2.mga5", rpm:"nvidia340-kernel-4.1.15-desktop-2.mga5~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-kernel-4.1.15-desktop586-2.mga5", rpm:"nvidia340-kernel-4.1.15-desktop586-2.mga5~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-kernel-4.1.15-server-2.mga5", rpm:"nvidia340-kernel-4.1.15-server-2.mga5~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-kernel-desktop-latest", rpm:"nvidia340-kernel-desktop-latest~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-kernel-desktop586-latest", rpm:"nvidia340-kernel-desktop586-latest~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-kernel-server-latest", rpm:"nvidia340-kernel-server-latest~340.93~5.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.1.15~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.1.15-desktop-2.mga5", rpm:"vboxadditions-kernel-4.1.15-desktop-2.mga5~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.1.15-desktop586-2.mga5", rpm:"vboxadditions-kernel-4.1.15-desktop586-2.mga5~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.1.15-server-2.mga5", rpm:"vboxadditions-kernel-4.1.15-server-2.mga5~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.1.15-desktop-2.mga5", rpm:"virtualbox-kernel-4.1.15-desktop-2.mga5~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.1.15-desktop586-2.mga5", rpm:"virtualbox-kernel-4.1.15-desktop586-2.mga5~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.1.15-server-2.mga5", rpm:"virtualbox-kernel-4.1.15-server-2.mga5~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.0.12~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.1.15-desktop-2.mga5", rpm:"xtables-addons-kernel-4.1.15-desktop-2.mga5~2.7~8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.1.15-desktop586-2.mga5", rpm:"xtables-addons-kernel-4.1.15-desktop586-2.mga5~2.7~8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.1.15-server-2.mga5", rpm:"xtables-addons-kernel-4.1.15-server-2.mga5~2.7~8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.7~8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.7~8.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.7~8.mga5", rls:"MAGEIA5"))) {
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
