# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63493");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
  script_cve_id("CVE-2009-0599", "CVE-2009-0600");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-1798 (wireshark)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Few minor security issues were fixed in new version of wireshark. Security-
related bugs in the Tektronix K12 and NetScreen file formats have been fixed.

ChangeLog:

  * Tue Feb 17 2009 Radek Vokal  1.0.6-1

  - add netdump2 support

  - fix SELinux issues, remove pie patch

  - upgrade to 1.0.6");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update wireshark' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1798");
  script_tag(name:"summary", value:"The remote host is missing an update to wireshark
announced via advisory FEDORA-2009-1798.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=485888");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=485889");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
