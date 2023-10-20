# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63781");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0385", "CVE-2009-1274");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3433 (xine-lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Maintenance release. Fixes two security problems (CVE-2009-0385, CVE-2009-1274)
and a few miscellaneous bugs.

ChangeLog:

  * Fri Apr  3 2009 Rex Dieter  - 1.1.16.3-1

  - xine-lib-1.1.16.3, plugin-abi 1.26

  * Thu Mar 26 2009 Rex Dieter  - 1.1.16.2-6

  - add-mime-for-mod.patch

  * Tue Mar 10 2009 Kevin Kofler  - 1.1.16.2-5

  - rebuild for new ImageMagick

  * Thu Feb 26 2009 Fedora Release Engineering  - 1.1.16.2-4

  * Fri Feb 20 2009 Rex Dieter  - 1.1.16.2-3

  - xine-lib-devel muiltilib conflict (#477226)

  * Tue Feb 17 2009 Rex Dieter  - 1.1.16.2-2

  - xine-lib-safe-audio-pause3 patch (#486255, kdebug#180339)

  * Tue Feb 10 2009 Kevin Kofler  - 1.1.16.2-1.1

  - also patch the caca version check in configure(.ac)

  * Tue Feb 10 2009 Rex Dieter  - 1.1.16.2-1

  - xine-lib-1.1.16.2

  * Mon Feb  9 2009 Rex Dieter  - 1.1.16.1-4

  - gapless-race-fix patch (kdebug#180339)

  * Sat Feb  7 2009 Rex Dieter  - 1.1.16.1-3

  - safe-audio-pause patch (kdebug#180339)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xine-lib' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3433");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-lib
announced via advisory FEDORA-2009-3433.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495031");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.16.3~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-devel", rpm:"xine-lib-devel~1.1.16.3~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-extras", rpm:"xine-lib-extras~1.1.16.3~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-pulseaudio", rpm:"xine-lib-pulseaudio~1.1.16.3~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-debuginfo", rpm:"xine-lib-debuginfo~1.1.16.3~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
