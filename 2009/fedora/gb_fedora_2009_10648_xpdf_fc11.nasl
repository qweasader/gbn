# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66092");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609", "CVE-2009-3605");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-10648 (xpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.

Update Information:

  - apply xpdf-3.02pl4 security patch to fix:
    CVE-2009-1188/CVE-2009-3603, CVE-2009-3604, CVE-2009-3606,
    CVE-2009-3608, CVE-2009-3609

ChangeLog:

  * Fri Oct 16 2009 Tom spot Callaway  - 1:3.02-15

  - apply xpdf-3.02pl4 security patch to fix:
CVE-2009-3603, CVE-2009-3604, CVE-2009-3605, CVE-2009-3606
CVE-2009-3608, CVE-2009-3609");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xpdf' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10648");
  script_tag(name:"summary", value:"The remote host is missing an update to xpdf
announced via advisory FEDORA-2009-10648.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495907");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526911");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526877");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526637");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526893");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~15.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-debuginfo", rpm:"xpdf-debuginfo~3.02~15.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
