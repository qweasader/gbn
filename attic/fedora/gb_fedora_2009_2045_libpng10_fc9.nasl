# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63530");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
  script_cve_id("CVE-2009-0040", "CVE-2008-1382");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-2045 (libpng10)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This release fixes a vulnerability in which some arrays of pointers are not
initialized prior to using malloc to define the pointers. If the application
runs out of memory while executing the allocation loop (which can be forced by
malevolent input), libpng10 will jump to a cleanup process that attempts to free
all of the pointers, including the undefined ones.    This issue has been
assigned CVE-2009-0040");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libpng10' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2045");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng10
announced via advisory FEDORA-2009-2045.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=486355");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
