# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53698");
  script_version("2023-06-29T08:15:14+0000");
  script_tag(name:"last_modification", value:"2023-06-29 08:15:14 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0693", "CVE-2003-0695");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 382-2 (ssh)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20382-2");
  script_tag(name:"insight", value:"This advisory is an addition to the earlier DSA-382-1 advisory: two more
buffer handling problems have been found in addition to the one
described in DSA-382-1. It is not known if these bugs are exploitable,
but as a precaution an upgrade is advised.

For the Debian stable distribution these bugs have been fixed in version
1:3.4p1-1.woody.2 .

Please note that if a machine is setup to install packages from
proposed-updates it will not automatically install this update.");
  script_tag(name:"summary", value:"The remote host is missing an update to ssh announced via advisory DSA 382-2.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-382)' (OID: 1.3.6.1.4.1.25623.1.0.53699).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);