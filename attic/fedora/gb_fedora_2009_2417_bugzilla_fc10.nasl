# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63602");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2008-4437", "CVE-2008-6098", "CVE-2009-0481", "CVE-2009-0483", "CVE-2009-0484", "CVE-2009-0485", "CVE-2009-0486", "CVE-2009-0482");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-2417 (bugzilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"ChangeLog:

  * Thu Mar  5 2009 Itamar Reis Peixoto  3.2.2-2

  - fix from BZ #474250 Comment #16, from Chris Eveleigh -->

  - add python BR for contrib subpackage

  - fix description

  - change Requires perl-SOAP-Lite to perl(SOAP::Lite) according guidelines

  * Sun Mar  1 2009 Itamar Reis Peixoto  3.2.2-1

  - thanks to Chris Eveleigh

  - for contributing with patches :-)

  - Upgrade to upstream 3.2.2 to fix multiple security vulns

  - Removed old perl_requires exclusions, added new ones for RADIUS, Oracle and sanitycheck.cgi

  - Added Oracle to supported DBs in description (and moved line breaks)

  - Include a patch to fix max_allowed_packet warning when using with mysql

  * Sat Feb 28 2009 Itamar Reis Peixoto  3.0.8-1

  - Upgrade to 3.0.8, fix #466077 #438080

  - fix macro in changelog rpmlint warning

  - fix files-attr-not-set rpmlint warning for doc and contrib sub-packages

  * Mon Feb 23 2009 Fedora Release Engineering  - 3.0.4-4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update bugzilla' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2417");
  script_tag(name:"summary", value:"The remote host is missing an update to bugzilla
announced via advisory FEDORA-2009-2417.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=465956");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484755");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484805");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484807");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484811");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484812");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484813");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484806");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
