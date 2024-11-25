# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66194");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-0689", "CVE-2009-3380", "CVE-2009-3382", "CVE-2009-3370", "CVE-2009-3274", "CVE-2009-3373", "CVE-2009-3372", "CVE-2009-3375", "CVE-2009-3374", "CVE-2009-3376");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-10981 (blam)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to new upstream Firefox version 3.0.15, fixing multiple security issues

Update also includes all packages depending on gecko-libs rebuilt against
new version of Firefox / XULRunner.

ChangeLog:

  * Tue Oct 27 2009 Jan Horak  - 1.8.5-15

  - Rebuild against newer gecko");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update blam' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10981");
  script_tag(name:"summary", value:"The remote host is missing an update to blam
announced via advisory FEDORA-2009-10981.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530567");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530569");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530168");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530167");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530162");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530157");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530156");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530155");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=524815");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530151");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
