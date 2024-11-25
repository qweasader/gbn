# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1817.1");
  script_cve_id("CVE-2023-1945", "CVE-2023-1999", "CVE-2023-29531", "CVE-2023-29532", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536", "CVE-2023-29539", "CVE-2023-29541", "CVE-2023-29542", "CVE-2023-29545", "CVE-2023-29548", "CVE-2023-29550");
  script_tag(name:"creation_date", value:"2023-04-12 04:19:34 +0000 (Wed, 12 Apr 2023)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 08:51:31 +0000 (Tue, 27 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1817-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1817-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231817-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2023:1817-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Firefox Extended Support Release 102.10.0 ESR (bsc#1210212)
CVE-2023-29531: Out-of-bound memory access in WebGL on macOS CVE-2023-29532: Mozilla Maintenance Service Write-lock bypass CVE-2023-29533: Fullscreen notification obscured CVE-2023-1999: Double-free in libwebp CVE-2023-29535: Potential Memory Corruption following Garbage Collector compaction CVE-2023-29536: Invalid free from JavaScript code CVE-2023-29539: Content-Disposition filename truncation leads to Reflected File Download CVE-2023-29541: Files with malicious extensions could have been downloaded unsafely on Linux CVE-2023-29542: Bypass of file download extension restrictions CVE-2023-29545: Windows Save As dialog resolved environment variables CVE-2023-1945: Memory Corruption in Safe Browsing Code CVE-2023-29548: Incorrect optimization result on ARM64 CVE-2023-29550: Memory safety bugs fixed in Firefox 112 and Firefox ESR 102.10");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~102.10.0~150000.150.82.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~102.10.0~150000.150.82.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~102.10.0~150000.150.82.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~102.10.0~150000.150.82.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~102.10.0~150000.150.82.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~102.10.0~150000.150.82.1", rls:"SLES15.0SP1"))) {
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
