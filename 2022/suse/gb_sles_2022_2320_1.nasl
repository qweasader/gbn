# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2320.1");
  script_cve_id("CVE-2022-2200", "CVE-2022-2226", "CVE-2022-31744", "CVE-2022-34468", "CVE-2022-34470", "CVE-2022-34472", "CVE-2022-34478", "CVE-2022-34479", "CVE-2022-34481", "CVE-2022-34484");
  script_tag(name:"creation_date", value:"2022-07-08 04:33:24 +0000 (Fri, 08 Jul 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 15:52:00 +0000 (Wed, 04 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2320-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222320-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2022:2320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

 - CVE-2022-2200: Undesired attributes could be set as part of prototype
 pollution (bmo#1771381)
 - CVE-2022-2226: An email with a mismatching OpenPGP signature date was
 accepted as valid (bmo#1775441)
 - CVE-2022-31744: CSP bypass enabling stylesheet injection (bmo#1757604)
 - CVE-2022-34468: CSP sandbox header without `allow-scripts` can be
 bypassed via retargeted javascript: URI (bmo#1768537)
 - CVE-2022-34470: Use-after-free in nsSHistory (bmo#1765951)
 - CVE-2022-34472: Unavailable PAC file resulted in OCSP requests being
 blocked (bmo#1770123)
 - CVE-2022-34478: Microsoft protocols can be attacked if a user accepts
 a prompt (bmo#1773717)
 - CVE-2022-34479: A popup window could be resized in a way to overlay
 the address bar with web content (bmo#1745595)
 - CVE-2022-34481: Potential integer overflow in ReplaceElementsAt
 (bmo#1497246)
 - CVE-2022-34484: Memory safety bugs fixed in Thunderbird 91.11 and
 Thunderbird 102 (bmo#1763634, bmo#1772651)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.11.0~150200.8.76.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.11.0~150200.8.76.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.11.0~150200.8.76.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.11.0~150200.8.76.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.11.0~150200.8.76.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.11.0~150200.8.76.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.11.0~150200.8.76.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.11.0~150200.8.76.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.11.0~150200.8.76.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.11.0~150200.8.76.1", rls:"SLES15.0SP4"))) {
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
