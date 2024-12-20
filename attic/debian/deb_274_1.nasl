# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53341");
  script_cve_id("CVE-2003-0167");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-274-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-274-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-274");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mutt' package(s) announced via the DSA-274-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-274)' (OID: 1.3.6.1.4.1.25623.1.0.53354).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Byrial Jensen discovered a couple of off-by-one buffer overflow in the IMAP code of Mutt, a text-oriented mail reader supporting IMAP, MIME, GPG, PGP and threading. This problem could potentially allow a remote malicious IMAP server to cause a denial of service (crash) and possibly execute arbitrary code via a specially crafted mail folder.

For the stable distribution (woody) this problem has been fixed in version 1.3.28-2.2.

The old stable distribution (potato) is also affected by this problem and an update will follow.

For the unstable distribution (sid) this problem has been fixed in version 1.4.0 and above.

We recommend that you upgrade your mutt package.");

  script_tag(name:"affected", value:"'mutt' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);