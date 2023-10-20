# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58686");
  script_version("2023-06-29T08:15:14+0000");
  script_tag(name:"last_modification", value:"2023-06-29 08:15:14 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-3905");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1389-1 (zoph)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201389-1");
  script_tag(name:"insight", value:"It was discovered that zoph, a web based photo management system,
performs insufficient input sanitising, which allows SQL injection.

For the oldstable distribution (sarge) this problem has been fixed in
version 0.3.3-12sarge2.

For the stable distribution (etch) this problem has been fixed in
version 0.6-2.1etch1.

For the unstable distribution (sid) this problem has been fixed in
version 0.7.0.2-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your zoph package.");
  script_tag(name:"summary", value:"The remote host is missing an update to zoph announced via advisory DSA 1389-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1389)' (OID: 1.3.6.1.4.1.25623.1.0.58693).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);