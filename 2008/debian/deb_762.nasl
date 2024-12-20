# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54384");
  script_cve_id("CVE-2005-2250", "CVE-2005-2277");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-762-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-762-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-762");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'affix' package(s) announced via the DSA-762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Finisterre discovered two problems in the Bluetooth FTP client from affix, user space utilities for the Affix Bluetooth protocol stack. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2005-2250

A buffer overflow allows remote attackers to execute arbitrary code via a long filename in an OBEX file share.

CAN-2005-2277

Missing input sanitising before executing shell commands allow an attacker to execute arbitrary commands as root.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 2.1.1-2.

For the unstable distribution (sid) these problems have been fixed in version 2.1.2-2.

We recommend that you upgrade your affix package.");

  script_tag(name:"affected", value:"'affix' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"affix", ver:"2.1.1-2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaffix-dev", ver:"2.1.1-2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaffix2", ver:"2.1.1-2", rls:"DEB3.1"))) {
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
