# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60800");
  script_cve_id("CVE-2008-0165");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1553-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1553-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1553");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ikiwiki' package(s) announced via the DSA-1553-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1553)' (OID: 1.3.6.1.4.1.25623.1.0.61106).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that ikiwiki, a Wiki implementation, does not guard password and content changes against cross-site request forgery (CSRF) attacks.

For the stable distribution (etch), this problem has been fixed in version 1.33.5.

For the unstable distribution (sid), this problem has been fixed in version 2.42.

We recommend that you upgrade your ikiwiki package.");

  script_tag(name:"affected", value:"'ikiwiki' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);