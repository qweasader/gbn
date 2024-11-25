# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58587");
  script_cve_id("CVE-2007-3999", "CVE-2007-4743");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1367-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1367");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-1367-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1367)' (OID: 1.3.6.1.4.1.25623.1.0.58589).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a buffer overflow of the RPC library of the MIT Kerberos reference implementation allows the execution of arbitrary code.

The oldstable distribution (sarge) is not affected by this problem.

For the stable distribution (etch) this problem has been fixed in version 1.4.4-7etch3.

For the unstable distribution (sid) this problem has been fixed in version 1.6.dfsg.1-7.

We recommend that you upgrade your Kerberos packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);