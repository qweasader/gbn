# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833565");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-3676");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 14:28:27 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:56:28 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2023:0375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0375-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7QZT42MLW43OAUZVU7TCPFA26L43FXGE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2023:0375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

     IBM Security Update November 2022: (bsc#1205302, bsc#1204703)

  - CVE-2022-3676: A security vulnerability was fixed in version 8.0.7.20,
       adding the reference here.");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.68.1", rls:"openSUSELeap15.4"))) {
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