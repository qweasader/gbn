# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3745.1");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-38505", "CVE-2021-38506", "CVE-2021-38507", "CVE-2021-38508", "CVE-2021-38509", "CVE-2021-38510", "CVE-2021-43534", "CVE-2021-43535");
  script_tag(name:"creation_date", value:"2021-11-21 03:21:15 +0000 (Sun, 21 Nov 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 19:53:33 +0000 (Mon, 13 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3745-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3745-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213745-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2021:3745-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

MozillaFirefox was updated to Extended Support Release 91.3.0 ESR

Fixed: Various stability, functionality, and security fixes

MFSA 2021-49 (bsc#1192250)

 * CVE-2021-38503: iframe sandbox rules did not apply to XSLT stylesheets
 * CVE-2021-38504: Use-after-free in file picker dialog
 * CVE-2021-38505: Windows 10 Cloud Clipboard may have recorded sensitive
 user data
 * CVE-2021-38506: Firefox could be coaxed into going into fullscreen
 mode without notification or warning
 * CVE-2021-38507: Opportunistic Encryption in HTTP2 could be used to
 bypass the Same-Origin-Policy on services hosted on other ports
 * CVE-2021-38508: Permission Prompt could be overlaid, resulting in user
 confusion and potential spoofing
 * CVE-2021-38509: Javascript alert box could have been spoofed onto an
 arbitrary domain
 * CVE-2021-38510: Download Protections were bypassed by .inetloc files
 on Mac OS
 * CVE-2021-43535: Use-after-free in HTTP2 Session object
 * CVE-2021-43534: Memory safety bugs fixed in Firefox 94 and Firefox ESR
 91.3");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Module for Desktop Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~91.3.0~152.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~91.3.0~152.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~91.3.0~152.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~91.3.0~152.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~91.3.0~152.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~91.3.0~152.6.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~91.3.0~152.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~91.3.0~152.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~91.3.0~152.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~91.3.0~152.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~91.3.0~152.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~91.3.0~152.6.1", rls:"SLES15.0SP3"))) {
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
