# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2561.1");
  script_cve_id("CVE-2021-46657", "CVE-2021-46658", "CVE-2021-46659", "CVE-2021-46661", "CVE-2021-46663", "CVE-2021-46664", "CVE-2021-46665", "CVE-2021-46668", "CVE-2021-46669", "CVE-2022-21427", "CVE-2022-24048", "CVE-2022-24050", "CVE-2022-24051", "CVE-2022-24052", "CVE-2022-27376", "CVE-2022-27377", "CVE-2022-27378", "CVE-2022-27379", "CVE-2022-27380", "CVE-2022-27381", "CVE-2022-27382", "CVE-2022-27383", "CVE-2022-27384", "CVE-2022-27386", "CVE-2022-27387", "CVE-2022-27444", "CVE-2022-27445", "CVE-2022-27446", "CVE-2022-27447", "CVE-2022-27448", "CVE-2022-27449", "CVE-2022-27451", "CVE-2022-27452", "CVE-2022-27455", "CVE-2022-27456", "CVE-2022-27457", "CVE-2022-27458");
  script_tag(name:"creation_date", value:"2022-07-28 04:36:26 +0000 (Thu, 28 Jul 2022)");
  script_version("2024-05-02T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-05-02 05:05:31 +0000 (Thu, 02 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 13:54:58 +0000 (Thu, 21 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2561-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2561-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222561-1/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-1068-release-notes");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-1068-changelog");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-1067-release-notes");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-1067-changelog");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-1066-release-notes");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-1066-changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2022:2561-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

Added mariadb-galera (jsc#SLE-22245)

Update to 10.6.8 (bsc#1199928):

CVE-2021-46669 (bsc#1199928)

CVE-2022-27376 (bsc#1198628)

CVE-2022-27377 (bsc#1198603)

CVE-2022-27378 (bsc#1198604)

CVE-2022-27379 (bsc#1198605)

CVE-2022-27380 (bsc#1198606)

CVE-2022-27381 (bsc#1198607)

CVE-2022-27382 (bsc#1198609)

CVE-2022-27383 (bsc#1198610)

CVE-2022-27384 (bsc#1198611)

CVE-2022-27386 (bsc#1198612)

CVE-2022-27387 (bsc#1198613)

CVE-2022-27444 (bsc#1198634)

CVE-2022-27445 (bsc#1198629)

CVE-2022-27446 (bsc#1198630)

CVE-2022-27447 (bsc#1198631)

CVE-2022-27448 (bsc#1198632)

CVE-2022-27449 (bsc#1198633)

CVE-2022-27451 (bsc#1198639)

CVE-2022-27452 (bsc#1198640)

CVE-2022-27455 (bsc#1198638)

CVE-2022-27456 (bsc#1198635)

CVE-2022-27457 (bsc#1198636)

CVE-2022-27458 (bsc#1198637)

The following issue is not affecting this package: CVE-2022-21427

Update to 10.6.7 (bsc#1196016):

CVE-2021-46665, CVE-2021-46664, CVE-2021-46661, CVE-2021-46668,
 CVE-2021-46663

Update to 10.6.6:

CVE-2022-24052, CVE-2022-24051, CVE-2022-24050, CVE-2022-24048,
 CVE-2021-46659 (bsc#1195339)

The following issues have been fixed already but didn't have CVE references:

CVE-2021-46658 (bsc#1195334)

CVE-2021-46657 (bsc#1195325)

Non security fixes:

Skip failing tests for s390x, fixes bsc#1195076

External refernences:

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd-devel", rpm:"libmariadbd-devel~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19-debuginfo", rpm:"libmariadbd19-debuginfo~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.6.8~150400.3.7.1", rls:"SLES15.0SP4"))) {
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
