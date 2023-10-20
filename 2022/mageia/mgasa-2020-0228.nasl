# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0228");
  script_cve_id("CVE-2020-10711", "CVE-2020-12464", "CVE-2020-12659", "CVE-2020-12770", "CVE-2020-13143");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 19:15:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0228");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0228.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26661");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.9");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.11");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.12");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.13");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.6.14");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2020-0228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on the upstream 5.6.14 kernel and fixes at least
the following security issues:

A NULL pointer dereference flaw was found in the Linux kernel's SELinux
subsystem in versions before 5.7. This flaw occurs while importing the
Commercial IP Security Option (CIPSO) protocol's category bitmap into
the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine.
While processing the CIPSO restricted bitmap tag in the
'cipso_v4_parsetag_rbm' routine, it sets the security attribute to
indicate that the category bitmap is present, even if it has not been
allocated. This issue leads to a NULL pointer dereference issue while
importing the same category bitmap into SELinux. This flaw allows a
remote network user to crash the system kernel, resulting in a denial
of service (CVE-2020-10711).

usb_sg_cancel in drivers/usb/core/message.c in the Linux kernel before
5.6.8 has a use-after-free because a transfer occurs without a
reference(CVE-2020-12464).

An issue was discovered in the Linux kernel before 5.6.7. xdp_umem_reg
in net/xdp/xdp_umem.c has an out-of-bounds write (by a user with the
CAP_NET_ADMIN capability) because of a lack of headroom validation
(CVE-2020-12659).

An issue was discovered in the Linux kernel through 5.6.11. sg_write
lacks an sg_remove_request call in a certain failure case
(CVE-2020-12770).

gadget_dev_desc_UDC_store in drivers/usb/gadget/configfs.c in the Linux
kernel through 5.6.13 relies on kstrdup without considering the
possibility of an internal '\0' value, which allows attackers to trigger
an out-of-bounds read (CVE-2020-13143).

For other fixes and changes in this update, see the refenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.6.14-1.mga7", rpm:"kernel-linus-5.6.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.6.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.6.14-1.mga7", rpm:"kernel-linus-devel-5.6.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.6.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.6.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.6.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.6.14-1.mga7", rpm:"kernel-linus-source-5.6.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.6.14~1.mga7", rls:"MAGEIA7"))) {
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
