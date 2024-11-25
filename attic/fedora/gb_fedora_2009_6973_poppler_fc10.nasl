# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64300");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187", "CVE-2009-1188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-6973 (poppler)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

An update to address jbig2-related security issues.
ChangeLog:

  * Fri Jan 23 2009 Rex Dieter  - 0.8.7-6

  - use backported jbig2_security patch from debian/ubuntu

  - poppler-data-0.2.1

  - --enable-libjpeg (speed)

  - track sonames

  * Tue Jan 20 2009 Rex Dieter  - 0.8.7-5

  - patch to workaround okular rendering hyperlinks (#480357)

  - add needed scriptlets

  - nuke rpaths

  * Sun Jan  4 2009 Matthias Clasen   - 0.8.7-4

  - Fix a problem with large images");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update poppler' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6973");
  script_tag(name:"summary", value:"The remote host is missing an update to poppler
announced via advisory FEDORA-2009-6973.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496942");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
