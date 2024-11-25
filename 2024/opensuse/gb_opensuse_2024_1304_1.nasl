# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856070");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-4218");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 09:15:08 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-04-17 01:01:09 +0000 (Wed, 17 Apr 2024)");
  script_name("openSUSE: Security Advisory for eclipse, maven (SUSE-SU-2024:1304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1304-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UDBYFGA6HQ7E2JZB6L777GSJOFZ5XPWJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse, maven'
  package(s) announced via the SUSE-SU-2024:1304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for eclipse, maven-surefire, tycho fixes the following issues:

  eclipse received the following security fix:

  * CVE-2023-4218: Fixed a bug where parsing files with xml content laeds to XXE
      attacks. (bsc#1216992)

  maven-sunfire was updated from version 2.22.0 to 2.22.2:

  * Changes in version 2.22.2:

  * Bugs fixed:

  * Fixed JUnit Runner that writes to System.out corrupts Surefires STDOUT when using JUnits Vintage Engine

  * Changes in version 2.22.1:

  * Bugs fixed:

  * Fixed Surefire unable to run testing suites in parallel

  * Fixed Git wrongly considering PNG files as changed when there is no change

  * Fixed the surefire XSD published on maven site lacking of some rerun element

  * Fixed XML Report elements rerunError, rerunFailure, flakyFailure, flakyError

  * Fixed overriding platform version through project/plugin dependencies

  * Fixed mixed up characters in standard output

  * Logs in Parallel Tests are mixed up when `forkMode=never` or `forkCount=0`

  * MIME type for javascript is now officially application/javascript

  * Improvements:

  * Elapsed time in XML Report should satisfy pattern in XSD.

  * Fix old test resources TEST-*.xml in favor of continuing with SUREFIRE-1550

  * Nil element failureMessage in failsafe-summary.xml should have self closed tag

  * Removed obsolete module `surefire-setup-integration-tests`

  * Support Java 11

  * Surefire should support parameterized reportsDirectory

  * Dependency upgrades:

  * Upgraded maven-plugins parent to version 32

  * Upgraded maven-plugins parent to version 33

  tycho received the following bug fixes:

  * Fixed build against maven-surefire 2.22.1 and newer

  * Fixed build against newer plexus-compiler

  * Fixed issues with plexus-archiver 4.4.0 and newer

  * Require explicitly artifacts that will not be required automatically any
      more

  ##");

  script_tag(name:"affected", value:"'eclipse, maven' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform-debuginfo", rpm:"eclipse-platform-debuginfo~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt-debuginfo", rpm:"eclipse-swt-debuginfo~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt", rpm:"eclipse-swt~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt-bootstrap", rpm:"eclipse-swt-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform", rpm:"eclipse-platform~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-bootstrap-debuginfo", rpm:"eclipse-bootstrap-debuginfo~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-core", rpm:"eclipse-emf-core~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-core-bootstrap", rpm:"eclipse-emf-core-bootstrap~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-equinox-osgi", rpm:"eclipse-equinox-osgi~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt-bootstrap-debuginfo", rpm:"eclipse-swt-bootstrap-debuginfo~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-pde-bootstrap", rpm:"eclipse-pde-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-contributor-tools", rpm:"eclipse-contributor-tools~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform-bootstrap", rpm:"eclipse-platform-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform-bootstrap-debuginfo", rpm:"eclipse-platform-bootstrap-debuginfo~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-debuginfo", rpm:"eclipse-debuginfo~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-bootstrap-debugsource", rpm:"eclipse-bootstrap-debugsource~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-pde", rpm:"eclipse-pde~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-equinox-osgi-bootstrap", rpm:"eclipse-equinox-osgi-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-debugsource", rpm:"eclipse-debugsource~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-xsd", rpm:"eclipse-emf-xsd~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-p2-discovery", rpm:"eclipse-p2-discovery~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-failsafe-plugin-bootstrap", rpm:"maven-failsafe-plugin-bootstrap~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-report-parser", rpm:"maven-surefire-report-parser~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tycho-javadoc", rpm:"tycho-javadoc~1.6.0~150200.4.9.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tycho", rpm:"tycho~1.6.0~150200.4.9.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin-bootstrap", rpm:"maven-surefire-plugin-bootstrap~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-sdk", rpm:"eclipse-emf-sdk~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-javadoc", rpm:"maven-surefire-javadoc~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-p2-discovery-bootstrap", rpm:"eclipse-p2-discovery-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jdt-bootstrap", rpm:"eclipse-jdt-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-report-plugin-bootstrap", rpm:"maven-surefire-report-plugin-bootstrap~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugins-javadoc", rpm:"maven-surefire-plugins-javadoc~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-runtime", rpm:"eclipse-emf-runtime~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit5-javadoc", rpm:"maven-surefire-provider-junit5-javadoc~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jdt", rpm:"eclipse-jdt~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tycho-bootstrap", rpm:"tycho-bootstrap~1.6.0~150200.4.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-report-plugin", rpm:"maven-surefire-report-plugin~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit5", rpm:"maven-surefire-provider-junit5~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-failsafe-plugin", rpm:"maven-failsafe-plugin~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform-debuginfo", rpm:"eclipse-platform-debuginfo~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt-debuginfo", rpm:"eclipse-swt-debuginfo~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt", rpm:"eclipse-swt~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt-bootstrap", rpm:"eclipse-swt-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform", rpm:"eclipse-platform~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-bootstrap-debuginfo", rpm:"eclipse-bootstrap-debuginfo~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-core", rpm:"eclipse-emf-core~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-core-bootstrap", rpm:"eclipse-emf-core-bootstrap~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-equinox-osgi", rpm:"eclipse-equinox-osgi~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt-bootstrap-debuginfo", rpm:"eclipse-swt-bootstrap-debuginfo~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-pde-bootstrap", rpm:"eclipse-pde-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-contributor-tools", rpm:"eclipse-contributor-tools~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform-bootstrap", rpm:"eclipse-platform-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform-bootstrap-debuginfo", rpm:"eclipse-platform-bootstrap-debuginfo~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-debuginfo", rpm:"eclipse-debuginfo~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-bootstrap-debugsource", rpm:"eclipse-bootstrap-debugsource~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-pde", rpm:"eclipse-pde~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-equinox-osgi-bootstrap", rpm:"eclipse-equinox-osgi-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-debugsource", rpm:"eclipse-debugsource~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-xsd", rpm:"eclipse-emf-xsd~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-p2-discovery", rpm:"eclipse-p2-discovery~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-failsafe-plugin-bootstrap", rpm:"maven-failsafe-plugin-bootstrap~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-report-parser", rpm:"maven-surefire-report-parser~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tycho-javadoc", rpm:"tycho-javadoc~1.6.0~150200.4.9.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tycho", rpm:"tycho~1.6.0~150200.4.9.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin-bootstrap", rpm:"maven-surefire-plugin-bootstrap~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-sdk", rpm:"eclipse-emf-sdk~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-javadoc", rpm:"maven-surefire-javadoc~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-p2-discovery-bootstrap", rpm:"eclipse-p2-discovery-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jdt-bootstrap", rpm:"eclipse-jdt-bootstrap~4.15~150200.4.16.5", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-report-plugin-bootstrap", rpm:"maven-surefire-report-plugin-bootstrap~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugins-javadoc", rpm:"maven-surefire-plugins-javadoc~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-runtime", rpm:"eclipse-emf-runtime~2.22.0~150200.4.9.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit5-javadoc", rpm:"maven-surefire-provider-junit5-javadoc~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jdt", rpm:"eclipse-jdt~4.15~150200.4.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tycho-bootstrap", rpm:"tycho-bootstrap~1.6.0~150200.4.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-report-plugin", rpm:"maven-surefire-report-plugin~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit5", rpm:"maven-surefire-provider-junit5~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-failsafe-plugin", rpm:"maven-failsafe-plugin~2.22.2~150200.3.9.9.1", rls:"openSUSELeap15.5"))) {
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
