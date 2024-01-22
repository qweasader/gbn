# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63303");
  script_cve_id("CVE-2008-4770");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1716-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1716-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1716-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1716");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vnc4' package(s) announced via the DSA-1716-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that xvnc4viewer, a virtual network computing client software for X, is prone to an integer overflow via a malicious encoding value that could lead to arbitrary code execution.

For the stable distribution (etch) this problem has been fixed in version 4.1.1+X4.3.0-21+etch1.

For the unstable (sid) distribution this problem has been fixed in version 4.1.1+X4.3.0-31.

For the testing (lenny) distribution this problem will be fixed soon.

We recommend that you upgrade your vnc4 packages.");

  script_tag(name:"affected", value:"'vnc4' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vnc4-common", ver:"4.1.1+X4.3.0-21+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vnc4server", ver:"4.1.1+X4.3.0-21+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvnc4viewer", ver:"4.1.1+X4.3.0-21+etch1", rls:"DEB4"))) {
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
