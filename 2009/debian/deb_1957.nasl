# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66598");
  script_cve_id("CVE-2009-3575");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1957)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1957");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1957");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1957");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'aria2' package(s) announced via the DSA-1957 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that aria2, a high speed download utility, is prone to a buffer overflow in the DHT routing code, which might lead to the execution of arbitrary code.

The oldstable distribution (etch) is not affected by this problem.

For the stable distribution (lenny), this problem has been fixed in version 0.14.0-1+lenny1. Binaries for powerpc, arm, ia64 and hppa will be provided once they are available.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 1.2.0-1.

We recommend that you upgrade your aria2 packages.");

  script_tag(name:"affected", value:"'aria2' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"aria2", ver:"0.14.0-1+lenny1", rls:"DEB5"))) {
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
