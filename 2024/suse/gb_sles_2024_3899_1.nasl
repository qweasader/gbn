# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3899.1");
  script_cve_id("CVE-2024-10458", "CVE-2024-10459", "CVE-2024-10460", "CVE-2024-10461", "CVE-2024-10462", "CVE-2024-10463", "CVE-2024-10464", "CVE-2024-10465", "CVE-2024-10466", "CVE-2024-10467");
  script_tag(name:"creation_date", value:"2024-11-05 04:16:50 +0000 (Tue, 05 Nov 2024)");
  script_version("2024-11-06T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-11-06 05:05:44 +0000 (Wed, 06 Nov 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-04 13:26:32 +0000 (Mon, 04 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3899-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3899-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243899-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2024:3899-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:
Firefox Extended Support Release 128.4.0 ESR (bsc#1231879):

CVE-2024-10458: Permission leak via embed or object elements CVE-2024-10459: Use-after-free in layout with accessibility CVE-2024-10460: Confusing display of origin for external protocol handler prompt CVE-2024-10461: XSS due to Content-Disposition being ignored in multipart/x-mixed-replace response CVE-2024-10462: Origin of permission prompt could be spoofed by long URL CVE-2024-10463: Cross origin video frame leak CVE-2024-10464: History interface could have been used to cause a Denial of Service condition in the browser CVE-2024-10465: Clipboard 'paste' button persisted across tabs CVE-2024-10466: DOM push subscription message could hang Firefox CVE-2024-10467: Memory safety bugs fixed in Firefox 132, Thunderbird 132, Firefox ESR 128.4, and Thunderbird 128.4");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.4.0~112.234.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~128.4.0~112.234.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~128.4.0~112.234.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.4.0~112.234.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.4.0~112.234.2", rls:"SLES12.0SP5"))) {
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
