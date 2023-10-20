# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3586.1");
  script_cve_id("CVE-2021-3667");
  script_tag(name:"creation_date", value:"2021-11-02 14:44:50 +0000 (Tue, 02 Nov 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 20:48:00 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3586-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213586-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2021:3586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvirt fixes the following issues:

CVE-2021-3667: Fixed a DoS vulnerability in the libvirt
 virStoragePoolLookupByTargetPath API. (bsc#1188843)");

  script_tag(name:"affected", value:"'libvirt' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE MicroOS 5.0.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt-debugsource", rpm:"libvirt-debugsource~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs", rpm:"libvirt-libs~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs-debuginfo", rpm:"libvirt-libs-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin", rpm:"libvirt-admin~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin-debuginfo", rpm:"libvirt-admin-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-bash-completion", rpm:"libvirt-bash-completion~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-debuginfo", rpm:"libvirt-client-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-debuginfo", rpm:"libvirt-daemon-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface-debuginfo", rpm:"libvirt-daemon-driver-interface-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl", rpm:"libvirt-daemon-driver-libxl~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl-debuginfo", rpm:"libvirt-daemon-driver-libxl-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc-debuginfo", rpm:"libvirt-daemon-driver-lxc-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network-debuginfo", rpm:"libvirt-daemon-driver-network-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev-debuginfo", rpm:"libvirt-daemon-driver-nodedev-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter-debuginfo", rpm:"libvirt-daemon-driver-nwfilter-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu-debuginfo", rpm:"libvirt-daemon-driver-qemu-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret-debuginfo", rpm:"libvirt-daemon-driver-secret-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core", rpm:"libvirt-daemon-driver-storage-core~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core-debuginfo", rpm:"libvirt-daemon-driver-storage-core-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk", rpm:"libvirt-daemon-driver-storage-disk~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk-debuginfo", rpm:"libvirt-daemon-driver-storage-disk-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi", rpm:"libvirt-daemon-driver-storage-iscsi~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi-debuginfo", rpm:"libvirt-daemon-driver-storage-iscsi-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical", rpm:"libvirt-daemon-driver-storage-logical~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical-debuginfo", rpm:"libvirt-daemon-driver-storage-logical-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath", rpm:"libvirt-daemon-driver-storage-mpath~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath-debuginfo", rpm:"libvirt-daemon-driver-storage-mpath-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd", rpm:"libvirt-daemon-driver-storage-rbd~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd-debuginfo", rpm:"libvirt-daemon-driver-storage-rbd-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi", rpm:"libvirt-daemon-driver-storage-scsi~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi-debuginfo", rpm:"libvirt-daemon-driver-storage-scsi-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-hooks", rpm:"libvirt-daemon-hooks~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-qemu", rpm:"libvirt-daemon-qemu~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-xen", rpm:"libvirt-daemon-xen~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock-debuginfo", rpm:"libvirt-lock-sanlock-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss", rpm:"libvirt-nss~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss-debuginfo", rpm:"libvirt-nss-debuginfo~6.0.0~13.21.1", rls:"SLES15.0SP2"))) {
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
