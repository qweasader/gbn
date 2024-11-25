# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852836");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760",
                "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764",
                "CVE-2019-15903");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-14 19:15:00 +0000 (Sat, 14 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:34:31 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for MozillaFirefox, MozillaFirefox-branding-SLE (openSUSE-SU-2019:2451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2451-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, '
  package(s) announced via the openSUSE-SU-2019:2451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, MozillaFirefox-branding-SLE fixes the
  following issues:

  Changes in MozillaFirefox:

  Security issues fixed:

  - CVE-2019-15903: Fixed a heap overflow in the expat library
  (bsc#1149429).

  - CVE-2019-11757: Fixed a use-after-free when creating index updates in
  IndexedDB (bsc#1154738).

  - CVE-2019-11758: Fixed a potentially exploitable crash due to 360 Total
  Security (bsc#1154738).

  - CVE-2019-11759: Fixed a stack buffer overflow in HKDF output
  (bsc#1154738).

  - CVE-2019-11760: Fixed a stack buffer overflow in WebRTC networking
  (bsc#1154738).

  - CVE-2019-11761: Fixed an unintended access to a privileged JSONView
  object (bsc#1154738).

  - CVE-2019-11762: Fixed a same-origin-property violation (bsc#1154738).

  - CVE-2019-11763: Fixed an XSS bypass (bsc#1154738).

  - CVE-2019-11764: Fixed several memory safety bugs (bsc#1154738).

  Non-security issues fixed:

  - Added Provides-line for translations-common (bsc#1153423).

  - Moved some settings from branding-package here (bsc#1153869).

  - Disabled DoH by default.

  Changes in MozillaFirefox-branding-SLE:

  - Moved extensions preferences to core package (bsc#1153869).


  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2451=1");

  script_tag(name:"affected", value:"'MozillaFirefox, ' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-openSUSE", rpm:"MozillaFirefox-branding-openSUSE~68~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.2.0~lp151.2.18.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-esr-branding-openSUSE", rpm:"firefox-esr-branding-openSUSE~68~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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
