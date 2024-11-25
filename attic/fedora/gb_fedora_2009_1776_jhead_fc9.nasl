# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63492");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
  script_cve_id("CVE-2008-4640", "CVE-2008-4641", "CVE-2008-4575");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-1776 (jhead)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"* fixes CVE-2008-4640 jhead: arbitrary file deletion (#468056)    * fixes
CVE-2008-4641 jhead: command execution caused by incorrect handling of the shell
escapes (#468057)

ChangeLog:

  * Mon Feb 16 2009 Adrian Reber  - 2.86-1

  - updated to 2.86

  - fixes CVE-2008-4640 jhead: arbitrary file deletion (#468056)

  - fixes CVE-2008-4641 jhead: command execution caused by
incorrect handling of the shell escapes (#468057)

  - fixes build ignores optflags (#485697)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update jhead' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1776");
  script_tag(name:"summary", value:"The remote host is missing an update to jhead
announced via advisory FEDORA-2009-1776.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=468056");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=468057");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
