# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833421");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-46589", "CVE-2023-4658");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 19:11:01 +0000 (Mon, 04 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:51 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for tomcat10 (SUSE-SU-2024:0208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0208-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VQ4LAUX6VP4NBET7XIWLUS4MYZI6XS7C");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10'
  package(s) announced via the SUSE-SU-2024:0208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat10 fixes the following issues:

  Updated to Tomcat 10.1.18

  * CVE-2023-46589: Fixed HTTP request smuggling due to incorrect headers
      parsing (bsc#1217649)");

  script_tag(name:"affected", value:"'tomcat10' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-embed", rpm:"tomcat10-embed~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-docs-webapp", rpm:"tomcat10-docs-webapp~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsvc", rpm:"tomcat10-jsvc~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.18~150200.5.8.1", rls:"openSUSELeap15.5"))) {
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
