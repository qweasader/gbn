# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63669");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2008-6514");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3003 (compiz-fusion)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes a security issue in the expo plugin which allows local users
with physical access to drag the screen saver aside and access the locked
desktop by using Expo mouse shortcuts.
ChangeLog:

  * Tue Mar 24 2009 Adel Gadllah  0.7.6-6

  - Add fix for RH #491918, CVE-2008-6514

  * Sat Mar 14 2009 Adel Gadllah  0.7.6-5

  - Backport upstream fix for RH #474741");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update compiz-fusion' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3003");
  script_tag(name:"summary", value:"The remote host is missing an update to compiz-fusion
announced via advisory FEDORA-2009-3003.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491918");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
