# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3902.1");
  script_cve_id("CVE-2020-16042", "CVE-2020-26971", "CVE-2020-26973", "CVE-2020-26974", "CVE-2020-26978", "CVE-2020-35111", "CVE-2020-35112", "CVE-2020-35113");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-12 19:15:00 +0000 (Tue, 12 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3902-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203902-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2020:3902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Firefox Extended Support Release 78.6.0 ESR
 * Fixed: Various stability, functionality, and security fixes MFSA
 2020-55 (bsc#1180039)
 * CVE-2020-16042 (bmo#1679003) Operations on a BigInt could have caused
 uninitialized memory to be exposed
 * CVE-2020-26971 (bmo#1663466) Heap buffer overflow in WebGL
 * CVE-2020-26973 (bmo#1680084) CSS Sanitizer performed incorrect
 sanitization
 * CVE-2020-26974 (bmo#1681022) Incorrect cast of StyleGenericFlexBasis
 resulted in a heap use-after-free
 * CVE-2020-26978 (bmo#1677047) Internal network hosts could have been
 probed by a malicious webpage
 * CVE-2020-35111 (bmo#1657916) The proxy.onRequest API did not catch
 view-source URLs
 * CVE-2020-35112 (bmo#1661365) Opening an extension-less download may
 have inadvertently launched an executable instead
 * CVE-2020-35113 (bmo#1664831, bmo#1673589) Memory safety bugs fixed in
 Firefox 84 and Firefox ESR 78.6");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~78.6.0~3.122.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~78.6.0~3.122.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~78.6.0~3.122.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~78.6.0~3.122.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~78.6.0~3.122.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~78.6.0~3.122.1", rls:"SLES15.0SP1"))) {
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
