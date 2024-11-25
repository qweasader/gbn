# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131175");
  script_cve_id("CVE-2015-5156", "CVE-2015-5307", "CVE-2015-6937", "CVE-2015-7872", "CVE-2015-7884", "CVE-2015-7885", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8660");
  script_tag(name:"creation_date", value:"2016-01-14 05:28:48 +0000 (Thu, 14 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 17:31:24 +0000 (Mon, 18 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0014");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0014.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17396");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.13");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.14");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.15");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2016-0014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 4.1.15 longterm kernel and
fixes the following security issues:

The virtnet_probe function in drivers/net/virtio_net.c in the Linux kernel
before 4.2 attempts to support a FRAGLIST feature without proper memory
allocation, which allows guest OS users to cause a denial of service (buffer
overflow and memory corruption) via a crafted sequence of fragmented packets
(CVE-2015-5156).

The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through
4.6.x, allows guest OS users to cause a denial of service (host OS panic
or hang) by triggering many #AC (aka Alignment Check) exceptions, related
to svm.c and vmx.c (CVE-2015-5307).

The __rds_conn_create function in net/rds/connection.c in the Linux kernel
through 4.2.3 allows local users to cause a denial of service (NULL pointer
dereference and system crash) or possibly have unspecified other impact by
using a socket that was not properly bound (CVE-2015-6937).

The key_gc_unused_keys function in security/keys/gc.c in the Linux kernel
through 4.2.6 allows local users to cause a denial of service (OOPS) via
crafted keyctl commands (CVE-2015-7872).

The vivid_fb_ioctl function in drivers/media/platform/vivid/vivid-osd.c in
the Linux kernel through 4.3.3 does not initialize a certain structure
member, which allows local users to obtain sensitive information from
kernel memory via a crafted application (CVE-2015-7884).

The dgnc_mgmt_ioctl function in drivers/staging/dgnc/dgnc_mgmt.c in the
Linux kernel through 4.3.3 does not initialize a certain structure member,
which allows local users to obtain sensitive information from kernel memory
via a crafted application (CVE-2015-7885).

Felix Wilhelm discovered a race condition in the Xen paravirtualized
drivers which can cause double fetch vulnerabilities. An attacker in the
paravirtualized guest could exploit this flaw to cause a denial of service
(crash the host) or potentially execute arbitrary code on the host
(CVE-2015-8550 / XSA-155).

Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not
perform sanity checks on the device's state. An attacker could exploit
this flaw to cause a denial of service (NULL dereference) on the host
(CVE-2015-8551 / XSA-157).

Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not
perform sanity checks on the device's state. An attacker could exploit
this flaw to cause a denial of service by flooding the logging system
with WARN() messages causing the initial domain to exhaust disk space
(CVE-2015-8552 / XSA-157).

The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel
through 4.3.3 attempts to merge distinct setattr operations, which allows
local users to bypass intended access restrictions and modify the
attributes of arbitrary overlay files via a crafted application
(CVE-2015-8660).

For other fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.1.15-1.mga5", rpm:"kernel-linus-4.1.15-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.1.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.1.15-1.mga5", rpm:"kernel-linus-devel-4.1.15-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.1.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.1.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.1.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.1.15-1.mga5", rpm:"kernel-linus-source-4.1.15-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.1.15~1.mga5", rls:"MAGEIA5"))) {
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
