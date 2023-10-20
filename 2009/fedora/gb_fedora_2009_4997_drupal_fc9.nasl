# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63988");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
  script_cve_id("CVE-2008-3661");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 9 FEDORA-2009-4997 (drupal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

Fixes SA-CORE-2009-006

When outputting user-supplied data Drupal strips potentially dangerous HTML
attributes and tags or escapes characters which have a special meaning in HTML.
This output filtering secures the site against cross site scripting attacks via
user input.

Certain byte sequences that are valid in the UTF-8 specification
are potentially dangerous when interpreted as UTF-7. Internet Explorer
6 and 7 may decode these characters as UTF-7 if they appear before the
tag that specifies the page content as UTF-8, despite the
fact that Drupal also sends a real HTTP header specifying the content as UTF-8.
This enables attackers to execute cross site scripting attacks with UTF-7.

SA-CORE-2009-005 - Drupal core - Cross site scripting contained an
incomplete fix for the issue. HTML exports of books are still
vulnerable, which means that anyone with edit permissions for
pages in outlines is able to insert arbitrary HTML and script code
in these exports.

Additionally, the taxonomy module allows users with the
'administer taxonomy' permission to inject arbitrary HTML
and script code in the help text of any vocabulary.

ChangeLog:

  * Thu May 14 2009 Jon Ciesla  - 6.12-1

  - Update to 6.11, SA-CORE-2009-006.

  * Thu Apr 30 2009 Jon Ciesla  - 6.11-1

  - Update to 6.11, SA-CORE-2009-005.

  * Mon Apr 27 2009 Jon Ciesla  - 6.10-2

  - Added SELinux/sendmail note to README, BZ 497642.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

Remember to log in to your site as the admin user before upgrading
this package. After upgrading the package, browse to
http://example.com/drupal/update.php to run the upgrade script.

This update can be installed with the yum update program.  Use
su -c 'yum update drupal' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-4997");
  script_tag(name:"summary", value:"The remote host is missing an update to drupal
announced via advisory FEDORA-2009-4997.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"drupal", rpm:"drupal~6.12~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
