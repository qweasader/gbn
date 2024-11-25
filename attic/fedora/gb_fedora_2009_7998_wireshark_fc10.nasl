# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66442");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269", "CVE-2009-2559", "CVE-2009-2560", "CVE-2009-2561", "CVE-2009-2562", "CVE-2009-2563");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-7998 (wireshark)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Rebased to 1.2.x, fixing several security flaws.

ChangeLog:

  * Wed Jul 22 2009 Radek Vokal  1.2.1-1

  - upgrade to 1.2.1

  - fixes several security flaws");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update wireshark' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7998");
  script_tag(name:"summary", value:"The remote host is missing an update to wireshark
announced via advisory FEDORA-2009-7998.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512953");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513008");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512987");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512992");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
