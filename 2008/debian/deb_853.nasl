# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55600");
  script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-853)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-853");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-853");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-853");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ethereal' package(s) announced via the DSA-853 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security problems have been discovered in ethereal, a commonly used network traffic analyser. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2360

Memory allocation errors in the LDAP dissector can cause a denial of service.

CAN-2005-2361

Various errors in the AgentX, PER, DOCSIS, RADIUS, Telnet, IS-IS, HTTP, DCERPC, DHCP and SCTP dissectors can cause a denial of service.

CAN-2005-2363

Various errors in the SMPP, 802.3, H1 and DHCP dissectors can cause a denial of service.

CAN-2005-2364

Null pointer dereferences in the WBXML and GIOP dissectors can cause a denial of service.

CAN-2005-2365

A buffer overflow and null pointer dereferences in the SMB dissector can cause a denial of service.

CAN-2005-2366

Wrong address calculation in the BER dissector can cause an infinite loop or abortion.

CAN-2005-2367

Format string vulnerabilities in several dissectors allow remote attackers to write to arbitrary memory locations and thus gain privileges.

For the old stable distribution (woody) these problems have been fixed in version 0.9.4-1woody13.

For the stable distribution (sarge) these problems have been fixed in version 0.10.10-2sarge3.

For the unstable distribution (sid) these problems have been fixed in version 0.10.12-2.

We recommend that you upgrade your ethereal packages.");

  script_tag(name:"affected", value:"'ethereal' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.9.4-1woody13", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.9.4-1woody13", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.9.4-1woody13", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.9.4-1woody13", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
