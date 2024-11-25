# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66252");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-0692", "CVE-2009-1892");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-9075 (dhcp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Do not require policycoreutils when installing dhcp or dhclient packages.  If
you have the package installed, the /sbin/restorecon program will be used by
dhclient-script and the dhcpd init script.    This update to the dhcp package
includes fixes for CVE-2009-0692 and CVE-2009-1892.
Note: CVE-2009-0692 had no security consequences on Fedora, thanks to the
use of FORTIFY_SOURCE

ChangeLog:

  * Wed Aug 26 2009 David Cantrell  - 12:4.1.0p1-4

  - Do not require policycoreutils for dhclient subpackage, fix restorecon
calls in postinstall scriptlets (#519479)

  * Wed Aug 26 2009 David Cantrell  - 12:4.1.0p1-3

  - Do not require policycoreutils for post scriptlet (#519479)

  * Thu Aug  6 2009 David Cantrell  - 12:4.1.0p1-2

  - Add /usr/lib[64]/pm-utils/sleep.d/56dhclient to handle suspend and
resume with active dhclient leases (#479639)

  * Wed Aug  5 2009 David Cantrell  - 12:4.1.0p1-1

  - Upgrade to dhcp-4.1.0p1, which is the official upstream release to fix
CVE-2009-0692

  * Wed Aug  5 2009 David Cantrell  - 12:4.1.0-25

  - Fix for CVE-2009-0692

  - Fix for CVE-2009-1892 (#511834)

  - Disable patch for #514828 since that fix is still in updates-testing

  * Tue Aug  4 2009 David Cantrell  - 12:4.1.0-24

  - Correct lease file format written by dhclient (#514828)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update dhcp' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9075");
  script_tag(name:"summary", value:"The remote host is missing an update to dhcp
announced via advisory FEDORA-2009-9075.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=519479");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=511834");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
