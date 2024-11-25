# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0301.1");
  script_cve_id("CVE-2019-25031", "CVE-2019-25032", "CVE-2019-25033", "CVE-2019-25034", "CVE-2019-25035", "CVE-2019-25036", "CVE-2019-25037", "CVE-2019-25038", "CVE-2019-25039", "CVE-2019-25040", "CVE-2019-25041", "CVE-2019-25042", "CVE-2020-28935");
  script_tag(name:"creation_date", value:"2022-02-03 11:06:55 +0000 (Thu, 03 Feb 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-30 15:03:54 +0000 (Fri, 30 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0301-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220301-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound' package(s) announced via the SUSE-SU-2022:0301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unbound fixes the following issues:

CVE-2019-25031: Fixed configuration injection in
 create_unbound_ad_servers.sh upon a successful man-in-the-middle attack
 (bsc#1185382).

CVE-2019-25032: Fixed integer overflow in the regional allocator via
 regional_alloc (bsc#1185383).

CVE-2019-25033: Fixed integer overflow in the regional allocator via the
 ALIGN_UP macro (bsc#1185384).

CVE-2019-25034: Fixed integer overflow in
 sldns_str2wire_dname_buf_origin, leading to an out-of-bounds write
 (bsc#1185385).

CVE-2019-25035: Fixed out-of-bounds write in sldns_bget_token_par
 (bsc#1185386).

CVE-2019-25036: Fixed assertion failure and denial of service in
 synth_cname (bsc#1185387).

CVE-2019-25037: Fixed assertion failure and denial of service in
 dname_pkt_copy via an invalid packet (bsc#1185388).

CVE-2019-25038: Fixed integer overflow in a size calculation in
 dnscrypt/dnscrypt.c (bsc#1185389).

CVE-2019-25039: Fixed integer overflow in a size calculation in
 respip/respip.c (bsc#1185390).

CVE-2019-25040: Fixed infinite loop via a compressed name in
 dname_pkt_copy (bsc#1185391).

CVE-2019-25041: Fixed assertion failure via a compressed name in
 dname_pkt_copy (bsc#1185392).

CVE-2019-25042: Fixed out-of-bounds write via a compressed name in
 rdata_copy (bsc#1185393).

CVE-2020-28935: Fixed symbolic link traversal when writing PID file
 (bsc#1179191).");

  script_tag(name:"affected", value:"'unbound' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libunbound2", rpm:"libunbound2~1.6.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunbound2-debuginfo", rpm:"libunbound2-debuginfo~1.6.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor", rpm:"unbound-anchor~1.6.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor-debuginfo", rpm:"unbound-anchor-debuginfo~1.6.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debuginfo", rpm:"unbound-debuginfo~1.6.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debugsource", rpm:"unbound-debugsource~1.6.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.6.8~3.9.1", rls:"SLES15.0"))) {
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
