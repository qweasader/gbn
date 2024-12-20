# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64554");
  script_cve_id("CVE-2009-2470", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2665");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-8288 (perl-Gtk2-MozEmbed)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"This module allows you to use the Mozilla embedding widget from Perl.

Update Information:

Update to new upstream Firefox version 3.0.13, fixing multiple security issues.

Update also includes all packages depending on gecko-libs rebuilt against
new version of Firefox / XULRunner.

Note: Issues described in MFSA 2009-42 and MFSA 2009-43 were
previously addressed via rebase of the NSS packages.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl-Gtk2-MozEmbed' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8288");
  script_tag(name:"summary", value:"The remote host is missing an update to perl-Gtk2-MozEmbed
announced via advisory FEDORA-2009-8288.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"perl-Gtk2-MozEmbed", rpm:"perl-Gtk2-MozEmbed~0.08~6.fc10.4", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Gtk2-MozEmbed", rpm:"perl-Gtk2-MozEmbed~debuginfo~0.08", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
