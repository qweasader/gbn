# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0260");
  script_cve_id("CVE-2017-10810");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-13 19:32:45 +0000 (Thu, 13 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0260)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0260");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0260.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21391");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.75");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.76");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.77");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.78");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.79");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2017-0260 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 4.4.79 and fixes at least the
following security issues:

Linux kernel built with the VirtIO GPU driver(CONFIG_DRM_VIRTIO_GPU) support
is vulnerable to a memory leakage issue. It could occur while creating a
virtio gpu object in virtio_gpu_object_create(). A user/process could use
this flaw to leak host kernel memory potentially resulting in Dos
(CVE-2017-10810).

It also contains followup fixes to the Stack Clash (CVE-2017-1000370,
CVE-2017-1000371) security issues resolved in kernels released at end
of June, 2017.

For other upstream fixes in this update, read the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.4.79-1.mga5", rpm:"kernel-linus-4.4.79-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.4.79~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.4.79-1.mga5", rpm:"kernel-linus-devel-4.4.79-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.4.79~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.4.79~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.4.79~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.4.79-1.mga5", rpm:"kernel-linus-source-4.4.79-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.4.79~1.mga5", rls:"MAGEIA5"))) {
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
