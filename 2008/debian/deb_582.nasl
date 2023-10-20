# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53274");
  script_cve_id("CVE-2004-0989");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-582)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-582");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-582");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-582");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml, libxml2' package(s) announced via the DSA-582 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'infamous41md' discovered several buffer overflows in libxml and libxml2, the XML C parser and toolkits for GNOME. Missing boundary checks could cause several buffers to be overflown, which may cause the client to execute arbitrary code.

The following vulnerability matrix lists corrected versions of these libraries:

For the stable distribution (woody) these problems have been fixed in version 1.8.17-2woody2 of libxml and in version 2.4.19-4woody2 of libxml2.

For the unstable distribution (sid) these problems have been fixed in version 1.8.17-9 of libxml and in version 2.6.11-5 of libxml2.

These problems have also been fixed in version 2.6.15-1 of libxml2 in the experimental distribution.

We recommend that you upgrade your libxml packages.");

  script_tag(name:"affected", value:"'libxml, libxml2' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxml-dev", ver:"1:1.8.17-2woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml1", ver:"1:1.8.17-2woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.4.19-4woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.4.19-4woody2", rls:"DEB3.0"))) {
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
