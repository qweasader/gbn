# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3281.1");
  script_cve_id("CVE-2022-2200", "CVE-2022-2226", "CVE-2022-2505", "CVE-2022-3032", "CVE-2022-3033", "CVE-2022-3034", "CVE-2022-31744", "CVE-2022-34468", "CVE-2022-34470", "CVE-2022-34472", "CVE-2022-34478", "CVE-2022-34479", "CVE-2022-34481", "CVE-2022-34484", "CVE-2022-36059", "CVE-2022-36314", "CVE-2022-36318", "CVE-2022-36319", "CVE-2022-38472", "CVE-2022-38473", "CVE-2022-38476", "CVE-2022-38477", "CVE-2022-38478");
  script_tag(name:"creation_date", value:"2022-09-16 04:59:03 +0000 (Fri, 16 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 15:52:00 +0000 (Wed, 04 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3281-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3281-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223281-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2022:3281-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Updated to Mozilla Thunderbird 102.2.2:
CVE-2022-3033: Fixed leaking of sensitive information when composing a
 response to an HTML email with a META refresh tag (bsc#1203007).

CVE-2022-3032: Fixed missing blocking of remote content specified in an
 HTML document that was nested inside an iframe's srcdoc attribute
 (bsc#1203007).

CVE-2022-3034: Fixed issue where iframe element in an HTML email could
 trigger a network request (bsc#1203007).

CVE-2022-36059: Fixed DoS in Matrix SDK bundled with Thunderbird service
 attack (bsc#1203007).

CVE-2022-38472: Fixed Address bar spoofing via XSLT error handling
 (bsc#1202645).

CVE-2022-38473: Fixed cross-origin XSLT Documents inheriting the
 parent's permissions (bsc#1202645).

CVE-2022-38476: Fixed data race and potential use-after-free in
 PK11_ChangePW (bsc#1202645).

CVE-2022-38477: Fixed memory safety bugs (bsc#1202645).

CVE-2022-38478: Fixed memory safety bugs (bsc#1202645).

CVE-2022-36319: Fixed mouse position spoofing with CSS transforms
 (bsc#1201758).

CVE-2022-36318: Fixed directory indexes for bundled resources reflected
 URL parameters (bsc#1201758).

CVE-2022-36314: Fixed unexpected network loads when opening local .lnk
 files (bsc#1201758).

CVE-2022-2505: Fixed memory safety bugs (bsc#1201758).

CVE-2022-34479: Fixed vulnerability which could overlay the address bar
 with web content (bsc#1200793).

CVE-2022-34470: Fixed use-after-free in nsSHistory (bsc#1200793).

CVE-2022-34468: Fixed CSP sandbox header without `allow-scripts` bypass
 via retargeted javascript (bsc#1200793).

CVE-2022-2226: Fixed emails with a mismatching OpenPGP signature date
 incorrectly accepted as valid (bsc#1200793).

CVE-2022-34481: Fixed integer overflow in ReplaceElementsAt
 (bsc#1200793).

CVE-2022-31744: Fixed CSP bypass enabling stylesheet injection
 (bsc#1200793).

CVE-2022-34472: Fixed unavailable PAC file resulting in OCSP requests
 being blocked (bsc#1200793).

CVE-2022-34478: Fixed Microsoft protocols attacks if a user accepts a
 prompt (bsc#1200793).

CVE-2022-2200: Fixed vulnerability where undesired attributes could be
 set as part of prototype pollution (bsc#1200793).

CVE-2022-34484: Fixed memory safety bugs (bsc#1200793).");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~102.2.2~150200.8.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~102.2.2~150200.8.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~102.2.2~150200.8.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~102.2.2~150200.8.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~102.2.2~150200.8.82.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~102.2.2~150200.8.82.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~102.2.2~150200.8.82.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~102.2.2~150200.8.82.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~102.2.2~150200.8.82.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~102.2.2~150200.8.82.1", rls:"SLES15.0SP4"))) {
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
