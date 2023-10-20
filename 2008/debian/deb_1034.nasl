# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56581");
  script_cve_id("CVE-2006-1260", "CVE-2006-1491");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1034");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1034");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1034");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'horde2' package(s) announced via the DSA-1034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Horde web application framework, which may lead to the execution of arbitrary web script code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-1260

Null characters in the URL parameter bypass a sanity check, which allowed remote attackers to read arbitrary files, which allowed information disclosure.

CVE-2006-1491

User input in the help viewer was passed unsanitised to the eval() function, which allowed injection of arbitrary web code.

The old stable distribution (woody) doesn't contain horde2 packages.

For the stable distribution (sarge) these problems have been fixed in version 2.2.8-1sarge2.

The unstable distribution (sid) does no longer contain horde2 packages.

We recommend that you upgrade your horde2 package.");

  script_tag(name:"affected", value:"'horde2' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"horde2", ver:"2.2.8-1sarge2", rls:"DEB3.1"))) {
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
