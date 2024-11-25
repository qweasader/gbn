# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64971");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-2730", "CVE-2008-4989");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 03:19:21 +0000 (Fri, 09 Feb 2024)");
  script_name("Fedora Core 10 FEDORA-2009-8622 (gnutls)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes handling of NUL characters in certificate  Common Name or
subjectAltName fields especially in regards to comparison to hostnames.

ChangeLog:

  * Wed Sep 23 2009 Tomas Mraz  2.4.2-5

  - fix handling of hostname in openpgp certificates

  * Fri Aug 14 2009 Tomas Mraz  2.4.2-4

  - fix CVE-2009-2730 - handling of NUL chars in certificate CNs and SANs");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gnutls' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8622");
  script_tag(name:"summary", value:"The remote host is missing an update to gnutls
announced via advisory FEDORA-2009-8622.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=516231");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
