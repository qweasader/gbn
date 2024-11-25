# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2586.1");
  script_cve_id("CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32745", "CVE-2022-32746");
  script_tag(name:"creation_date", value:"2022-08-01 04:49:26 +0000 (Mon, 01 Aug 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 18:09:32 +0000 (Mon, 29 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2586-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222586-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldb, samba' package(s) announced via the SUSE-SU-2022:2586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ldb, samba fixes the following issues:

CVE-2022-32746: Fixed a use-after-free occurring in database audit
 logging (bsc#1201490).

CVE-2022-32745: Fixed a remote server crash with an LDAP add or modify
 request (bsc#1201492).

CVE-2022-2031: Fixed AD restrictions bypass associated with changing
 passwords (bsc#1201495).

CVE-2022-32742: Fixed a memory leak in SMB1 (bsc#1201496).

CVE-2022-32744: Fixed an arbitrary password change request for any AD
 user (bsc#1201493).

The following security bugs were fixed:

samba was updated to 4.15.8:

Use pathref fd instead of io fd in vfs_default_durable_cookie,
 (bso#15042),

Setting fruit:resource = stream in vfs_fruit causes a panic, (bso#15099),

Add support for bind 9.18, (bso#14986),

logging dsdb audit to specific files does not work, (bso#15076),

vfs_gpfs with vfs_shadowcopy2 fail to restore file if original file had
 been deleted, (bso#15069),

netgroups support removed, (bso#15087), (bsc#1199247),

net ads info shows LDAP Server: 0.0.0.0 depending on contacted server,
 (bso#14674), (bsc#1199734),

waf produces incorrect names for python extensions with Python 3.11,
 (bso#15071),

smbclient commands del & deltree fail with
 NT_STATUS_OBJECT_PATH_NOT_FOUND with DFS, (bso#15100), (bsc#1200556),

vfs_gpfs recalls=no option prevents listing files, (bso#15055),

waf produces incorrect names for python extensions with Python 3.11,
 (bso#15071),

Compile error in source3/utils/regedit_hexedit.c, (bso#15091),

ldconfig: /lib64/libsmbconf.so.0 is not a symbolic link, (bso#15108),

smbd doesn't handle UPNs for looking up names, (bso#15054),

Out-by-4 error in smbd read reply max_send clamp, (bso#14443),

Move pdb backends from package samba-libs to package samba-client-libs
 and remove samba-libs requirement from samba-winbind, (bsc#1200964),
 (bsc#1198255),

Use the canonical realm name to refresh the Kerberos tickets,
 (bsc#1196224), (bso#14979),

Fix smbclient commands del & deltree failing with
 NT_STATUS_OBJECT_PATH_NOT_FOUND with DFS, (bso#15100), (bsc#1200556).

ldb was updated to version 2.4.3

Fix build problems, waf produces incorrect names for python extensions,
 (bso#15071),");

  script_tag(name:"affected", value:"'ldb, samba' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Availability 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Python2 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ldb-debugsource", rpm:"ldb-debugsource~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-tools", rpm:"ldb-tools~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-tools-debuginfo", rpm:"ldb-tools-debuginfo~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb-devel", rpm:"libldb-devel~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2", rpm:"libldb2~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2-32bit", rpm:"libldb2-32bit~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2-32bit-debuginfo", rpm:"libldb2-32bit-debuginfo~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2-debuginfo", rpm:"libldb2-debuginfo~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb", rpm:"python3-ldb~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb-debuginfo", rpm:"python3-ldb-debuginfo~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb-devel", rpm:"python3-ldb-devel~2.4.3~150300.3.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-32bit", rpm:"samba-ad-dc-libs-32bit~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-32bit-debuginfo", rpm:"samba-ad-dc-libs-32bit-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs", rpm:"samba-ad-dc-libs~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-debuginfo", rpm:"samba-ad-dc-libs-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph", rpm:"samba-ceph~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph-debuginfo", rpm:"samba-ceph-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit-debuginfo", rpm:"samba-client-32bit-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit", rpm:"samba-client-libs-32bit~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit-debuginfo", rpm:"samba-client-libs-32bit-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel-32bit", rpm:"samba-devel-32bit~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap-debuginfo", rpm:"samba-ldb-ldap-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-tool", rpm:"samba-tool~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit", rpm:"samba-winbind-libs-32bit~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit-debuginfo", rpm:"samba-winbind-libs-32bit-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-debuginfo", rpm:"samba-winbind-libs-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc", rpm:"samba-ad-dc~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-debuginfo", rpm:"samba-ad-dc-debuginfo~4.15.8+git.500.d5910280cc7~150300.3.37.1", rls:"SLES15.0SP3"))) {
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
