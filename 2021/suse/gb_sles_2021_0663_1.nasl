# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0663.1");
  script_cve_id("CVE-2019-17437", "CVE-2020-13987", "CVE-2020-13988", "CVE-2020-17437", "CVE-2020-17438");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-15 16:34:08 +0000 (Tue, 15 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0663-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210663-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-iscsi' package(s) announced via the SUSE-SU-2021:0663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-iscsi fixes the following issues:

Fixes for CVE-2019-17437, CVE-2020-17438, CVE-2020-13987 and CVE-2020-13988 (bsc#1179908):

check for TCP urgent pointer past end of frame

check for u8 overflow when processing TCP options

check for header length underflow during checksum calculation");

  script_tag(name:"affected", value:"'open-iscsi' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio", rpm:"iscsiuio~0.7.8.2~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio-debuginfo", rpm:"iscsiuio-debuginfo~0.7.8.2~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopeniscsiusr0_2_0", rpm:"libopeniscsiusr0_2_0~2.0.876~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopeniscsiusr0_2_0-debuginfo", rpm:"libopeniscsiusr0_2_0-debuginfo~2.0.876~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi", rpm:"open-iscsi~2.0.876~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-debuginfo", rpm:"open-iscsi-debuginfo~2.0.876~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-debugsource", rpm:"open-iscsi-debugsource~2.0.876~12.27.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio", rpm:"iscsiuio~0.7.8.2~12.27.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio-debuginfo", rpm:"iscsiuio-debuginfo~0.7.8.2~12.27.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopeniscsiusr0_2_0", rpm:"libopeniscsiusr0_2_0~2.0.876~12.27.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopeniscsiusr0_2_0-debuginfo", rpm:"libopeniscsiusr0_2_0-debuginfo~2.0.876~12.27.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi", rpm:"open-iscsi~2.0.876~12.27.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-debuginfo", rpm:"open-iscsi-debuginfo~2.0.876~12.27.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-debugsource", rpm:"open-iscsi-debugsource~2.0.876~12.27.2", rls:"SLES12.0SP5"))) {
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
