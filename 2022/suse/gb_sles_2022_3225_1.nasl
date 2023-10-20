# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3225.1");
  script_cve_id("CVE-2018-25032", "CVE-2022-32081", "CVE-2022-32083", "CVE-2022-32084", "CVE-2022-32085", "CVE-2022-32086", "CVE-2022-32087", "CVE-2022-32088", "CVE-2022-32089", "CVE-2022-32091");
  script_tag(name:"creation_date", value:"2022-09-12 05:00:44 +0000 (Mon, 12 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 19:51:00 +0000 (Fri, 26 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3225-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3225-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223225-1/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10426-release-notes");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10426-changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2022:3225-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

Update to 10.4.26:

CVE-2022-32089 (bsc#1201169)

CVE-2022-32081 (bsc#1201161)

CVE-2022-32091 (bsc#1201170)

CVE-2022-32084 (bsc#1201164)

CVE-2018-25032 (bsc#1197459)

CVE-2022-32088 (bsc#1201168)

CVE-2022-32087 (bsc#1201167)

CVE-2022-32086 (bsc#1201166)

CVE-2022-32085 (bsc#1201165)

CVE-2022-32083 (bsc#1201163)

Bugfixes:

Update mysql-systemd-helper to be aware of custom group (bsc#1200105).

External references:

[link moved to references]

[link moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd-devel", rpm:"libmariadbd-devel~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19-debuginfo", rpm:"libmariadbd19-debuginfo~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.4.26~150200.3.31.1", rls:"SLES15.0SP2"))) {
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
