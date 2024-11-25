# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64248");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 11 FEDORA-2009-5452 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Security update fixing DoS bugs in DTLS code.  CVE-2009-1377 CVE-2009-1378
CVE-2009-1379

ChangeLog:

  * Thu May 21 2009 Tomas Mraz  0.9.8k-5

  - fix CVE-2009-1377 CVE-2009-1378 CVE-2009-1379
(DTLS DoS problems) (#501253, #501254, #501572)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update openssl' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5452");
  script_tag(name:"summary", value:"The remote host is missing an update to openssl
announced via advisory FEDORA-2009-5452.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=501253");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=501254");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=501572");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
