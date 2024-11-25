# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0014.1");
  script_cve_id("CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023");
  script_tag(name:"creation_date", value:"2023-01-03 04:18:22 +0000 (Tue, 03 Jan 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 22:15:16 +0000 (Wed, 09 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0014-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230014-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2023:0014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

Update to 4.15.13

CVE-2022-37966 rc4-hmac Kerberos session keys issued to modern servers
 (bsc#1205385).

CVE-2022-37967 Kerberos constrained delegation ticket forgery possible
 against Samba AD DC (bsc#1205386).

CVE-2022-38023 RC4/HMAC-MD5 NetLogon Secure Channel is weak and should
 be avoided (bsc#1206504).

Fixed issue with bind start up (bsc#1205946).");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Availability 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Python2 15-SP3, SUSE Linux Enterprise Realtime Extension 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-32bit", rpm:"samba-ad-dc-libs-32bit~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-32bit-debuginfo", rpm:"samba-ad-dc-libs-32bit-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs", rpm:"samba-ad-dc-libs~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-debuginfo", rpm:"samba-ad-dc-libs-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph", rpm:"samba-ceph~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph-debuginfo", rpm:"samba-ceph-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit-debuginfo", rpm:"samba-client-32bit-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit", rpm:"samba-client-libs-32bit~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit-debuginfo", rpm:"samba-client-libs-32bit-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel-32bit", rpm:"samba-devel-32bit~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap-debuginfo", rpm:"samba-ldb-ldap-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-tool", rpm:"samba-tool~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit", rpm:"samba-winbind-libs-32bit~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit-debuginfo", rpm:"samba-winbind-libs-32bit-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-debuginfo", rpm:"samba-winbind-libs-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc", rpm:"samba-ad-dc~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-debuginfo", rpm:"samba-ad-dc-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"SLES15.0SP3"))) {
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
