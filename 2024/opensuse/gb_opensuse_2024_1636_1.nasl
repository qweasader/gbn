# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856162");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2024-29038", "CVE-2024-29039");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-24 01:10:43 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for tpm2.0 (SUSE-SU-2024:1636-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1636-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GJKYMHY2CTKPTK6HVWBIZBUXOZMOE2H7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2.0'
  package(s) announced via the SUSE-SU-2024:1636-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tpm2.0-tools fixes the following issues:

  * CVE-2024-29038: Fixed arbitrary quote data validation by tpm2_checkquote
      (bsc#1223687).

  * CVE-2024-29039: Fixed pcr selection value to be compared with the attest
      (bsc#1223689).

  ##");

  script_tag(name:"affected", value:"'tpm2.0' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debugsource", rpm:"tpm2.0-tools-debugsource~5.2~150400.6.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools", rpm:"tpm2.0-tools~5.2~150400.6.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debuginfo", rpm:"tpm2.0-tools-debuginfo~5.2~150400.6.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debugsource", rpm:"tpm2.0-tools-debugsource~5.2~150400.6.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools", rpm:"tpm2.0-tools~5.2~150400.6.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debuginfo", rpm:"tpm2.0-tools-debuginfo~5.2~150400.6.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debugsource", rpm:"tpm2.0-tools-debugsource~5.2~150400.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools", rpm:"tpm2.0-tools~5.2~150400.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debuginfo", rpm:"tpm2.0-tools-debuginfo~5.2~150400.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debugsource", rpm:"tpm2.0-tools-debugsource~5.2~150400.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools", rpm:"tpm2.0-tools~5.2~150400.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debuginfo", rpm:"tpm2.0-tools-debuginfo~5.2~150400.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debugsource", rpm:"tpm2.0-tools-debugsource~5.2~150400.6.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools", rpm:"tpm2.0-tools~5.2~150400.6.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debuginfo", rpm:"tpm2.0-tools-debuginfo~5.2~150400.6.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debugsource", rpm:"tpm2.0-tools-debugsource~5.2~150400.6.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools", rpm:"tpm2.0-tools~5.2~150400.6.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2.0-tools-debuginfo", rpm:"tpm2.0-tools-debuginfo~5.2~150400.6.3.1", rls:"openSUSELeapMicro5.4"))) {
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
