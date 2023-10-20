# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853450");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-10740", "CVE-2020-12625", "CVE-2020-12640", "CVE-2020-12641", "CVE-2020-15562", "CVE-2020-16145");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-24 18:15:00 +0000 (Thu, 24 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-25 03:01:03 +0000 (Fri, 25 Sep 2020)");
  script_name("openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2020:1516-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1516-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00083.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the openSUSE-SU-2020:1516-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for roundcubemail fixes the following issues:

  roundcubemail was upgraded to 1.3.15

  This is a security update to the LTS version 1.3. (boo#1175135)

  * Security: Fix cross-site scripting (XSS) via HTML messages with
  malicious svg content [CVE-2020-16145]

  * Security: Fix cross-site scripting (XSS) via HTML messages with
  malicious math content

  From 1.3.14 (boo#1173792 -> CVE-2020-15562)

  * Security: Fix cross-site scripting (XSS) via HTML messages with
  malicious svg/namespace

  From 1.3.13

  * Installer: Fix regression in SMTP test section (#7417)

  From 1.3.12

  * Security: Better fix for CVE-2020-12641 (boo#1171148)

  * Security: Fix XSS issue in template object 'username' (#7406)

  * Security: Fix couple of XSS issues in Installer (#7406)

  * Security: Fix cross-site scripting (XSS) via malicious XML attachment

  From 1.3.11 (boo#1171148 -> CVE-2020-12641 boo#1171040 -> CVE-2020-12625
  boo#1171149 -> CVE-2020-12640)

  * Enigma: Fix compatibility with Mail_Mime >= 1.10.5

  * Fix permissions on some folders created by bin/install-jsdeps.sh
  script (#6930)

  * Fix bug where inline images could have been ignored if Content-Id
  header contained redundant spaces (#6980)

  * Fix PHP Warning: Use of undefined constant LOG_EMERGE (#6991)

  * Fix PHP warning: 'array_merge(): Expected parameter 2 to be an array,
  null given in sendmail.inc (#7003)

  * Security: Fix XSS issue in handling of CDATA in HTML messages

  * Security: Fix remote code execution via crafted 'im_convert_path' or
  'im_identify_path' settings

  * Security: Fix local file inclusion (and code execution) via crafted
  'plugins' option

  * Security: Fix CSRF bypass that could be used to log out an
  authenticated user (#7302)

  From 1.3.10 (boo#1146286)

  * Managesieve: Fix so 'Create filter' option does not show up when
  Filters menu is disabled (#6723)

  * Enigma: Fix bug where revoked users/keys were not greyed out in key
  info

  * Enigma: Fix error message when trying to encrypt with a revoked key
  (#6607)

  * Enigma: Fix 'decryption oracle' bug [CVE-2019-10740] (#6638)

  * Fix compatibility with kolab/net_ldap3 > 1.0.7 (#6785)

  * Fix bug where bmp images couldn't be displayed on some systems (#6728)

  * Fix bug in parsing vCard data using PHP 7.3 due to an invalid regexp
  (#6744)

  * Fix bug where bold/strong text was converted to upper-case on
  html-to-text conversion (6758)

  * Fix bug in rcube_utils::parse_hosts() where %t, %d, %z could return
  only tld (#6746)

  * Fix bug where Next/Prev button in mail view didn't work with
  multi-folder search  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.3.15~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.3.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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