# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833398");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-51765", "CVE-2023-5176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:47 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-08 02:01:10 +0000 (Fri, 08 Mar 2024)");
  script_name("openSUSE: Security Advisory for sendmail (SUSE-SU-2024:0743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0743-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TAMS3GYWXYSKFZUOXMRAQMVTQKX2I74G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sendmail'
  package(s) announced via the SUSE-SU-2024:0743-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sendmail fixes the following issues:

  * CVE-2023-51765: Fixed new SMTP smuggling attack. (bsc#1218351)

  ##");

  script_tag(name:"affected", value:"'sendmail' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sendmail-starttls", rpm:"sendmail-starttls~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmilter-doc", rpm:"libmilter-doc~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-devel", rpm:"sendmail-devel~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmail-debuginfo", rpm:"rmail-debuginfo~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmilter1_0-debuginfo", rpm:"libmilter1_0-debuginfo~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmilter1_0", rpm:"libmilter1_0~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail", rpm:"sendmail~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-debuginfo", rpm:"sendmail-debuginfo~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmail", rpm:"rmail~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-debugsource", rpm:"sendmail-debugsource~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-starttls", rpm:"sendmail-starttls~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmilter-doc", rpm:"libmilter-doc~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-devel", rpm:"sendmail-devel~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmail-debuginfo", rpm:"rmail-debuginfo~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmilter1_0-debuginfo", rpm:"libmilter1_0-debuginfo~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmilter1_0", rpm:"libmilter1_0~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail", rpm:"sendmail~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-debuginfo", rpm:"sendmail-debuginfo~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmail", rpm:"rmail~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-debugsource", rpm:"sendmail-debugsource~8.15.2~150000.8.12.1", rls:"openSUSELeap15.5"))) {
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