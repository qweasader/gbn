# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.854685");
  script_version("2023-03-24T10:19:42+0000");
  script_cve_id("CVE-2021-23343", "CVE-2021-32803", "CVE-2021-32804", "CVE-2021-3807", "CVE-2021-3918", "CVE-2021-44906", "CVE-2021-44907", "CVE-2022-0235", "CVE-2022-21824");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-28 16:04:00 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-05-18 01:02:03 +0000 (Wed, 18 May 2022)");
  script_name("openSUSE: Security Advisory for nodejs10 (SUSE-SU-2022:1717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1717-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TVOYEYPIBP6X6SWPIBUXAZWP5TEMQQTM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs10'
  package(s) announced via the SUSE-SU-2022:1717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs10 fixes the following issues:

  - CVE-2021-23343: Fixed ReDoS via splitDeviceRe, splitTailRe and
       splitPathRe (bsc#1192153).

  - CVE-2021-32803: Fixed insufficient symlink protection in node-tar
       allowing arbitrary file creation and overwrite (bsc#1191963).

  - CVE-2021-32804: Fixed insufficient absolute path sanitization in
       node-tar allowing arbitrary file creation and overwrite (bsc#1191962).

  - CVE-2021-3918: Fixed improper controlled modification of object
       prototype attributes in json-schema (bsc#1192696).

  - CVE-2021-3807: Fixed regular expression denial of service (ReDoS)
       matching ANSI escape codes in node-ansi-regex (bsc#1192154).

  - CVE-2022-21824: Fixed prototype pollution via console.table
       (bsc#1194514).

  - CVE-2021-44906: Fixed prototype pollution in npm dependency
       (bsc#1198247).

  - CVE-2021-44907: Fixed insufficient sanitation in npm dependency
       (bsc#1197283).

  - CVE-2022-0235: Fixed passing of cookie data and sensitive headers to
       different hostnames in node-fetch-npm (bsc#1194819).");

  script_tag(name:"affected", value:"'nodejs10' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.44.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.44.1", rls:"openSUSELeap15.3"))) {
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