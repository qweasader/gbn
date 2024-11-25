# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64100");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2008-5557", "CVE-2008-5658", "CVE-2008-3658", "CVE-2008-5498", "CVE-2008-5814", "CVE-2009-0754", "CVE-2009-1271", "CVE-2008-2829", "CVE-2008-3660");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3848 (maniadrive)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to PHP 5.2.9

ChangeLog:

  * Thu Apr 16 2009 Remi Collet  - 1.2-13

  - Rebuild for php 5.2.9");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update maniadrive' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3848");
  script_tag(name:"summary", value:"The remote host is missing an update to maniadrive
announced via advisory FEDORA-2009-3848.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=478425");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=494530");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=459529");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=459572");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=452808");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=474824");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=478848");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479272");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
