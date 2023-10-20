# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2302.1");
  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7782", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7804", "CVE-2017-7807");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 15:14:00 +0000 (Fri, 03 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2302-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2302-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172302-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2017:2302-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to the ESR 52.3 release (bsc#1052829)
Following security issues were fixed:
* MFSA 2017-19/CVE-2017-7807: Domain hijacking through AppCache fallback
* MFSA 2017-19/CVE-2017-7791: Spoofing following page navigation with
 data: protocol and modal alerts
* MFSA 2017-19/CVE-2017-7792: Buffer overflow viewing certificates with an
 extremely long OID
* MFSA 2017-19/CVE-2017-7782: WindowsDllDetourPatcher allocates memory
 without DEP protections
* MFSA 2017-19/CVE-2017-7787: Same-origin policy bypass with iframes
 through page reloads
* MFSA 2017-19/CVE-2017-7786: Buffer overflow while painting
 non-displayable SVG
* MFSA 2017-19/CVE-2017-7785: Buffer overflow manipulating ARIA attributes
 in DOM
* MFSA 2017-19/CVE-2017-7784: Use-after-free with image observers
* MFSA 2017-19/CVE-2017-7753: Out-of-bounds read with cached style data
 and pseudo-elements
* MFSA 2017-19/CVE-2017-7798: XUL injection in the style editor in devtools
* MFSA 2017-19/CVE-2017-7804: Memory protection bypass through
 WindowsDllDetourPatcher
* MFSA 2017-19/CVE-2017-7779: Memory safety bugs fixed in Firefox 55 and
 Firefox ESR 52.3
* MFSA 2017-19/CVE-2017-7800: Use-after-free in WebSockets during
 disconnection
* MFSA 2017-19/CVE-2017-7801: Use-after-free with marquee during window
 resizing
* MFSA 2017-19/CVE-2017-7802: Use-after-free resizing image elements
* MFSA 2017-19/CVE-2017-7803: CSP containing 'sandbox' improperly applied This update also fixes:
- fixed firefox hangs after a while in FUTEX_WAIT_PRIVATE if cgroups
 enabled and running on cpu >=1 (bsc#1031485)
- The Itanium ia64 build was fixed.");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.3.0esr~72.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~52~24.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.3.0esr~72.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.3.0esr~72.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~52~24.5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.3.0esr~72.9.1", rls:"SLES11.0SP4"))) {
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
