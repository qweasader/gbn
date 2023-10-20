# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2103.1");
  script_cve_id("CVE-2019-13619");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-10 20:37:00 +0000 (Wed, 10 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2103-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192103-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2019:2103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark to version 2.4.16 fixes the following issues:

Security issue fixed:
CVE-2019-13619: ASN.1 BER and related dissectors crash (bsc#1141980).");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9-debuginfo", rpm:"libwireshark9-debuginfo~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7-debuginfo", rpm:"libwiretap7-debuginfo~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1-debuginfo", rpm:"libwscodecs1-debuginfo~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8-debuginfo", rpm:"libwsutil8-debuginfo~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~2.4.16~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9", rpm:"libwireshark9~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark9-debuginfo", rpm:"libwireshark9-debuginfo~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7", rpm:"libwiretap7~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap7-debuginfo", rpm:"libwiretap7-debuginfo~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1-debuginfo", rpm:"libwscodecs1-debuginfo~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8", rpm:"libwsutil8~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil8-debuginfo", rpm:"libwsutil8-debuginfo~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~2.4.16~3.31.1", rls:"SLES15.0SP1"))) {
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
