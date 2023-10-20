# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0264");
  script_cve_id("CVE-2022-2318", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-07-21 04:43:01 +0000 (Thu, 21 Jul 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0264");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0264.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30643");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.51");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.52");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.55");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-403.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-405.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-406.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.55 and fixes at least the
following security issues:

There are use-after-free vulnerabilities caused by timer handler in
net/rose/rose_timer.c of linux that allow attackers to crash linux kernel
without any privileges (CVE-2022-2318).

Xen Block and Network PV device frontends don't zero memory regions before
sharing them with the backend (CVE-2022-26365, CVE-2022-33740, XSA-403).
Additionally the granularity of the grant table doesn't allow sharing less
than a 4K page, leading to unrelated data residing in the same 4K page as
data shared with a backend being accessible by such backend (CVE-2022-33741,
CVE-2022-33742, XSA-403).

Xen network backend may cause Linux netfront to use freed SKBs While adding
logic to support XDP (eXpress Data Path), a code label was moved in a way
allowing for SKBs having references (pointers) retained for further
processing to nevertheless be freed (CVE-2022-33743, XSA-405).

Xen Arm guests can cause Dom0 DoS via PV devices When mapping pages of guests
on Arm, dom0 is using an rbtree to keep track of the foreign mappings.
Updating of that rbtree is not always done completely with the related lock
held, resulting in a small race window, which can be used by unprivileged
guests via PV devices to cause inconsistencies of the rbtree. These
in consistencies can lead to Denial of Service (DoS) of dom0, e.g. by
causing crashes or the inability to perform further mappings of other guests
memory pages (CVE-2022-33744, XSA-406).

An issue was discovered in the Linux kernel through 5.18.9. A type confusion
bug in nft_set_elem_init (leading to a buffer overflow) could be used by a
local attacker to escalate privileges (The attacker can obtain root access,
but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN
access) (CVE-2022-34918).

For other upstream fixes, see the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.55-1.mga8", rpm:"kernel-linus-5.15.55-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.55~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.55-1.mga8", rpm:"kernel-linus-devel-5.15.55-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.55~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.55~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.55~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.55-1.mga8", rpm:"kernel-linus-source-5.15.55-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.55~1.mga8", rls:"MAGEIA8"))) {
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
