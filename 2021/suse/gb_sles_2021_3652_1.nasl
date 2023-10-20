# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3652.1");
  script_cve_id("CVE-2017-6004", "CVE-2017-7186", "CVE-2017-7244", "CVE-2017-7245", "CVE-2017-7246", "CVE-2019-20838", "CVE-2020-14155");
  script_tag(name:"creation_date", value:"2021-11-11 07:47:56 +0000 (Thu, 11 Nov 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-17 10:29:00 +0000 (Fri, 17 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3652-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213652-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre' package(s) announced via the SUSE-SU-2021:3652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcre fixes the following issues:

Update pcre to version 8.45:

CVE-2020-14155: Fixed integer overflow via a large number after a '(?C'
 substring (bsc#1172974).

CVE-2019-20838: Fixed buffer over-read in JIT compiler (bsc#1172973).

CVE-2017-7244: Fixed invalid read in _pcre32_xclass() (bsc#1030807).

CVE-2017-7245: Fixed buffer overflow in the pcre32_copy_substring
 (bsc#1030805).

CVE-2017-7246: Fixed another buffer overflow in the
 pcre32_copy_substring (bsc#1030803).

CVE-2017-7186: Fixed denial of service caused by an invalid Unicode
 property lookup (bsc#1030066).

CVE-2017-6004: Fixed denial of service via crafted regular expression
 (bsc#1025709).");

  script_tag(name:"affected", value:"'pcre' package(s) on SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo-32bit", rpm:"libpcre1-debuginfo-32bit~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo", rpm:"libpcre1-debuginfo~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-debuginfo", rpm:"libpcre16-0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-debugsource", rpm:"pcre-debugsource~8.45~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~20140730~36.5.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-devel", rpm:"selinux-policy-devel~20140730~36.5.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~20140730~36.5.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo-32bit", rpm:"libpcre1-debuginfo-32bit~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo", rpm:"libpcre1-debuginfo~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-debuginfo", rpm:"libpcre16-0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-debuginfo", rpm:"libpcrecpp0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-debuginfo", rpm:"libpcreposix0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-debugsource", rpm:"pcre-debugsource~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.45~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~20140730~36.5.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-devel", rpm:"selinux-policy-devel~20140730~36.5.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~20140730~36.5.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo-32bit", rpm:"libpcre1-debuginfo-32bit~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo", rpm:"libpcre1-debuginfo~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-debuginfo", rpm:"libpcre16-0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-debuginfo", rpm:"libpcrecpp0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-debuginfo", rpm:"libpcreposix0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-debugsource", rpm:"pcre-debugsource~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.45~8.7.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~20140730~36.5.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-devel", rpm:"selinux-policy-devel~20140730~36.5.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~20140730~36.5.2", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo-32bit", rpm:"libpcre1-debuginfo-32bit~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo", rpm:"libpcre1-debuginfo~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-debuginfo", rpm:"libpcre16-0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-debuginfo", rpm:"libpcrecpp0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-debuginfo", rpm:"libpcreposix0-debuginfo~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-debugsource", rpm:"pcre-debugsource~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.45~8.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~20140730~36.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-devel", rpm:"selinux-policy-devel~20140730~36.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~20140730~36.5.2", rls:"SLES12.0SP5"))) {
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
