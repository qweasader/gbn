# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64402");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1391", "CVE-2008-2827", "CVE-2007-4829");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-7680 (perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This security update fixes an off-by-one overflow in Compress::Raw::Zlib
(CVE-2009-1391)  Moreover, it contains a subtle change to the configuration that
does not affect the Perl interpreter itself, but fixes the propagation of the
chosen options to the modules.  For example, a rebuild of perl-Wx against
perl-5.10.0-73 will fix bug 508496.

ChangeLog:

  * Tue Jul  7 2009 Stepan Kasal  - 4:5.10.0-73

  - re-enable tests

  * Tue Jul  7 2009 Stepan Kasal  - 4:5.10.0-72

  - move -DPERL_USE_SAFE_PUTENV to ccflags (#508496)

  * Mon Jun  8 2009 Marcela Mal�ov�  - 4:5.10.0-71

  - #504386 update of Compress::Raw::Zlib 2.020

  * Thu Jun  4 2009 Marcela Mal�ov�  - 4:5.10.0-70

  - update File::Spec (PathTools) to 3.30

  * Wed Jun  3 2009 Stepan Kasal  - 4:5.10.0-69

  - fix #221113, $! wrongly set when EOF is reached");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7680");
  script_tag(name:"summary", value:"The remote host is missing an update to perl
announced via advisory FEDORA-2009-7680.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504386");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=508496");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
