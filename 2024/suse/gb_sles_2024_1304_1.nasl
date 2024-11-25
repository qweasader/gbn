# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1304.1");
  script_cve_id("CVE-2023-4218");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2024-05-09T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-05-09 05:05:43 +0000 (Thu, 09 May 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 09:15:08 +0000 (Thu, 09 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1304-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241304-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse, maven-surefire, tycho' package(s) announced via the SUSE-SU-2024:1304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for eclipse, maven-surefire, tycho fixes the following issues:
eclipse received the following security fix:

CVE-2023-4218: Fixed a bug where parsing files with xml content laeds to XXE attacks. (bsc#1216992)

maven-sunfire was updated from version 2.22.0 to 2.22.2:


Changes in version 2.22.2:


Bugs fixed:

Fixed JUnit Runner that writes to System.out corrupts Surefire's STDOUT when using JUnit's Vintage
 Engine



Changes in version 2.22.1:


Bugs fixed:

Fixed Surefire unable to run testng suites in parallel Fixed Git wrongly considering PNG files as changed when there is no change Fixed the surefire XSD published on maven site lacking of some rerun element Fixed XML Report elements rerunError, rerunFailure, flakyFailure, flakyError Fixed overriding platform version through project/plugin dependencies Fixed mixed up characters in standard output Logs in Parallel Tests are mixed up when forkMode=never or forkCount=0 MIME type for javascript is now officially application/javascript



Improvements:

Elapsed time in XML Report should satisfy pattern in XSD.
Fix old test resources TEST-*.xml in favor of continuing with SUREFIRE-1550 Nil element 'failureMessage' in failsafe-summary.xml should have self closed tag Removed obsolete module surefire-setup-integration-tests Support Java 11 Surefire should support parameterized reportsDirectory



Dependency upgrades:

Upgraded maven-plugins parent to version 32 Upgraded maven-plugins parent to version 33



tycho received the following bug fixes:

Fixed build against maven-surefire 2.22.1 and newer Fixed build against newer plexus-compiler Fixed issues with plexus-archiver 4.4.0 and newer Require explicitely artifacts that will not be required automatically any more");

  script_tag(name:"affected", value:"'eclipse, maven-surefire, tycho' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Package Hub 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~2.22.2~150200.3.9.9.1", rls:"SLES15.0SP4"))) {
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
