# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0547");
  script_cve_id("CVE-2021-3667");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 20:48:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2021-0547)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0547");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0547.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29401");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-August/009329.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/K4QAQWSVV2PRNPOI4R3VBPRTRXS5NLQ5/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HWNKJO5VHRNPGVFUMEQ3V6RYIEYVWGLV/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the MGASA-2021-0547 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix deadlock on virStoragePoolLookupByTargetPath failure (bz #1986113)
(CVE-2021-3667)
More CAP_SETPCAP warning fixes (bz #1924218)
Handle unknown firmware.json errors");

  script_tag(name:"affected", value:"'libvirt' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64nss_libvirt2", rpm:"lib64nss_libvirt2~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt-devel", rpm:"lib64virt-devel~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt0", rpm:"lib64virt0~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_libvirt2", rpm:"libnss_libvirt2~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-utils", rpm:"libvirt-utils~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt0", rpm:"libvirt0~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-libvirt", rpm:"wireshark-libvirt~7.0.0~2.2.mga8", rls:"MAGEIA8"))) {
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
