# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856382");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2023-47272");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:22:50 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-08-22 04:00:23 +0000 (Thu, 22 Aug 2024)");
  script_name("openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2024:0257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0257-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JQ3GTO6YI3BLAIR7PQZYZ5LRFR7OKTWN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the openSUSE-SU-2024:0257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for roundcubemail fixes the following issues:

     Update to 1.6.7

     This is a security update to the stable version 1.6 of Roundcube Webmail.
     It provides a fix to a recently reported XSS vulnerabilities:

  * Fix cross-site scripting (XSS) vulnerability in handling SVG animate
         attributes. Reported by Valentin T. and Lutz Wolf of CrowdStrike.

  * Fix cross-site scripting (XSS) vulnerability in handling list columns
         from user preferences. Reported by Huy Nguyn Phm Nht.

  * Fix command injection via crafted im_convert_path/im_identify_path on
         Windows. Reported by Huy Nguyn Phm Nht.

       CHANGELOG

  * Makefile: Use phpDocumentor v3.4 for the Framework docs (#9313)

  * Fix bug where HTML entities in URLs were not decoded on HTML to plain
         text conversion (#9312)

  * Fix bug in collapsing/expanding folders with some special characters
         in names (#9324)

  * Fix PHP8 warnings (#9363, #9365, #9429)

  * Fix missing field labels in CSV import, for some locales (#9393)

  * Fix cross-site scripting (XSS) vulnerability in handling SVG animate
         attributes

  * Fix cross-site scripting (XSS) vulnerability in handling list columns
         from user preferences

  * Fix command injection via crafted im_convert_path/im_identify_path on
         Windows

     Update to 1.6.6:

  * Fix regression in handling LDAP search_fields configuration parameter
         (#9210)

  * Enigma: Fix finding of a private key when decrypting a message using
         GnuPG v2.3

  * Fix page jump menu flickering on click (#9196)

  * Update to TinyMCE 5.10.9 security release (#9228)

  * Fix PHP8 warnings (#9235, #9238, #9242, #9306)

  * Fix saving other encryption settings besides enigma's (#9240)

  * Fix unneeded php command use in installto.sh and deluser.sh scripts
         (#9237)

  * Fix TinyMCE localization installation (#9266)

  * Fix bug where trailing non-ascii characters in email addresses could
         have been removed in recipient input (#9257)

  * Fix IMAP GETMETADATA command with options - RFC5464

     Update to 1.6.5 (boo#1216895):

  * Fix cross-site scripting (XSS) vulnerability in setting
         Content-Type/Content-Disposition for attachment preview/download
         CVE-2023-47272

       Other changes:

  * Fix PHP8 fatal error when parsing a malformed BODYSTRUCTURE (#9171)

  * Fix duplicated Inbox folder on IMAP servers that do not use Inbox
         folder with all capi ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.7~bp155.2.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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