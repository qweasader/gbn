# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2307.1");
  script_cve_id("CVE-2021-3670");
  script_tag(name:"creation_date", value:"2022-07-07 04:41:01 +0000 (Thu, 07 Jul 2022)");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 18:12:00 +0000 (Mon, 29 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2307-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222307-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldb, samba' package(s) announced via the SUSE-SU-2022:2307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ldb, samba fixes the following issues:

ldb was updated to version 2.4.2 to fix:

Fix for CVE-2021-3670, ensure that the LDB request has not timed out
 during filter processing as the LDAP server MaxQueryDuration is
 otherwise not honoured.

samba was updated to fix:

Revert NIS support removal, (bsc#1199247),

Use requires_eq macro to require the libldb2 version available at
 samba-dsdb-modules build time, (bsc#1199362),

Add missing samba-client requirement to samba-winbind package,
 (bsc#1198255),

Update to 4.15.7

Share and server swapped in smbget password prompt, (bso#14831),

Durable handles won't reconnect if the leased file is written to,
 (bso#15022),

rmdir silently fails if directory contains unreadable files and hide
 unreadable is yes, (bso#15023),

SMB2_CLOSE_FLAGS_FULL_INFORMATION fails to return information
 on renamed file handle, (bso#15038),

vfs_shadow_copy2 breaks 'smbd async dosmode' sync fallback, (bso#14957),

shadow_copy2 fails listing snapshotted dirs with shadow:fixinodes,
 (bso#15035),

PAM Kerberos authentication incorrectly fails with a clock skew error,
 (bso#15046),

username map - samba erroneously applies unix group memberships to user
 account entries, (bso#15041),

NT_STATUS_ACCESS_DENIED translates into EPERM instead of EACCES in
 SMBC_server_internal, (bso#14983),

Simple bind doesn't work against an RODC (with non-preloaded users),
 (bso#13879),

Crash of winbind on RODC, (bso#14641),

uncached logon on RODC always fails once, (bso#14865),

KVNO off by 100000, (bso#14951),

LDAP simple binds should honour 'old password allowed period',
 (bso#15001),

wbinfo -a doesn't work reliable with upn names, (bso#15003),

Simple bind doesn't work against an RODC (with non-preloaded users),
 (bso#13879),

Uninitialized litemask in variable in vfs_gpfs module, (bso#15027),

Regression: create krb5 conf = yes doesn't work with a single KDC,
 (bso#15016),

Add provides to samba-client-libs package to fix upgrades from previous
 versions, (bsc#1197995),

Add missing samba-libs requirement to samba-winbind package,
 (bsc#1198255),

Update to 4.15.6

Renaming file on DFS root fails with NT_STATUS_OBJECT_PATH_NOT_FOUND,
 (bso#14169),

Samba does not response STATUS_INVALID_PARAMETER when opening 2
 objects with same lease key, (bso#14737),

NT error code is not set when overwriting a file during rename in
 libsmbclient, (bso#14938),

Fix ldap simple bind with TLS auditing, (bso#14996),

net ads info shows LDAP Server: 0.0.0.0 depending on contacted server,
 (bso#14674),

Problem when winbind renews Kerberos, (bso#14979), (bsc#1196224),

pam_winbind will not allow gdm login if password about to expire,
 (bso#8691),

virusfilter_vfs_openat: Not scanned: Directory or special file,
 (bso#14971),

DFS fix for AIX broken, (bso#13631),

Solaris and AIX acl modules: wrong function arguments, (bso#14974),

Function aixacl_sys_acl_get_file not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ldb, samba' package(s) on SUSE Linux Enterprise High Availability 15-SP4, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ldb-debugsource", rpm:"ldb-debugsource~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-tools", rpm:"ldb-tools~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-tools-debuginfo", rpm:"ldb-tools-debuginfo~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb-devel", rpm:"libldb-devel~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2", rpm:"libldb2~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2-32bit", rpm:"libldb2-32bit~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2-32bit-debuginfo", rpm:"libldb2-32bit-debuginfo~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2-debuginfo", rpm:"libldb2-debuginfo~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb", rpm:"python3-ldb~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb-debuginfo", rpm:"python3-ldb-debuginfo~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb-devel", rpm:"python3-ldb-devel~2.4.2~150400.4.3.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs", rpm:"samba-ad-dc-libs~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-debuginfo", rpm:"samba-ad-dc-libs-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph", rpm:"samba-ceph~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph-debuginfo", rpm:"samba-ceph-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit", rpm:"samba-client-libs-32bit~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit-debuginfo", rpm:"samba-client-libs-32bit-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap-debuginfo", rpm:"samba-ldb-ldap-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-debuginfo", rpm:"samba-winbind-libs-debuginfo~4.15.7+git.376.dd43aca9ab2~150400.3.5.3", rls:"SLES15.0SP4"))) {
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
