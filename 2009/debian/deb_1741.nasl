# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63606");
  script_cve_id("CVE-2008-6393");
  script_tag(name:"creation_date", value:"2009-03-19 23:52:38 +0000 (Thu, 19 Mar 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1741-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1741-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1741-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1741");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'psi' package(s) announced via the DSA-1741-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesus Olmos Gonzalez discovered that an integer overflow in the PSI Jabber client may lead to remote denial of service.

The old stable distribution (etch) is not affected.

For the stable distribution (lenny), this problem has been fixed in version 0.11-9.

For the unstable distribution (sid), this problem has been fixed in version 0.12.1-1.

We recommend that you upgrade your psi package.");

  script_tag(name:"affected", value:"'psi' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"psi", ver:"0.11-9", rls:"DEB5"))) {
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
