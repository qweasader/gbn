# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53697");
  script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-382-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-382-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-382");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ssh' package(s) announced via the DSA-382-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-382)' (OID: 1.3.6.1.4.1.25623.1.0.53698).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bug has been found in OpenSSH's buffer handling where a buffer could be marked as grown when the actual reallocation failed.

DSA-382-2: This advisory is an addition to the earlier DSA-382-1 advisory: two more buffer handling problems have been found in addition to the one described in DSA-382-1. It is not known if these bugs are exploitable, but as a precaution an upgrade is advised.

DSA-382-3: This advisory is an addition to the earlier DSA-382-1 and DSA-382-2 advisories: Solar Designer found four more bugs in OpenSSH that may be exploitable.

For the Debian stable distribution (woody) these bugs have been fixed in version 1:3.4p1-1.woody.3.");

  script_tag(name:"affected", value:"'ssh' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);