# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58596");
  script_cve_id("CVE-2007-4730");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1372-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1372-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1372");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xorg-server' package(s) announced via the DSA-1372-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1372)' (OID: 1.3.6.1.4.1.25623.1.0.58691).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aaron Plattner discovered a buffer overflow in the Composite extension of the X.org X server, which can lead to local privilege escalation.

The oldstable distribution (sarge) is not affected by this problem.

For the stable distribution (etch) this problem has been fixed in version 1.1.1-21etch1.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your xorg-server packages.");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);