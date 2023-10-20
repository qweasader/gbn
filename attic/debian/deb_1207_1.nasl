# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57579");
  script_version("2023-06-29T08:15:14+0000");
  script_tag(name:"last_modification", value:"2023-06-29 08:15:14 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-1678", "CVE-2006-2418", "CVE-2005-3621", "CVE-2005-3665", "CVE-2006-5116");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1207-1 (phpmyadmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge2.

For the upcoming stable release (etch) and unstable distribution (sid)
these problems have been fixed in version 2.9.0.3-1.

  We recommend that you upgrade your phpmyadmin package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201207-1");
  script_tag(name:"summary", value:"The remote host is missing an update to phpmyadmin announced via advisory DSA 1207-1.  Several remote vulnerabilities have been discovered in phpMyAdmin, a program to administrate MySQL over the web. The Common Vulnerabilities and Exposures project identifies the following problems:  CVE-2005-3621  CRLF injection vulnerability allows remote attackers to conduct HTTP response splitting attacks.  CVE-2005-3665  Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via the (1) HTTP_HOST variable and (2) various scripts in the libraries directory that handle header generation.  CVE-2006-1678  Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via scripts in the themes directory.  CVE-2006-2418  A cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or HTML via the db parameter of footer.inc.php.  CVE-2006-5116  A remote attacker could overwrite internal variables through the _FILES global variable.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1207)' (OID: 1.3.6.1.4.1.25623.1.0.57591).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);