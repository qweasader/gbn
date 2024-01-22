# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63394");
  script_cve_id("CVE-2009-0361");
  script_tag(name:"creation_date", value:"2009-02-13 19:43:17 +0000 (Fri, 13 Feb 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1722-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1722-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1722-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1722");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpam-heimdal' package(s) announced via the DSA-1722-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Derek Chan discovered that the PAM module for the Heimdal Kerberos implementation allows reinitialisation of user credentials when run from a setuid context, resulting in potential local denial of service by overwriting the credential cache file or to local privilege escalation.

For the stable distribution (etch), this problem has been fixed in version 2.5-1etch1.

For the upcoming stable distribution (lenny), this problem has been fixed in version 3.10-2.1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your libpam-heimdal package.");

  script_tag(name:"affected", value:"'libpam-heimdal' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-heimdal", ver:"2.5-1etch1", rls:"DEB4"))) {
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
