# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2133");
  script_cve_id("CVE-2010-4336");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2133-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2133-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2133");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'collectd' package(s) announced via the DSA-2133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that collectd, a statistics collection and monitoring daemon, is prone to a denial of service attack via a crafted network packet.

For the stable distribution (lenny), this problem has been fixed in version 4.4.2-3+lenny1.

For the testing distribution (squeeze), this problem has been fixed in version 4.10.1-1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 4.10.1-2.1.

This advisory only contains the packages for the alpha, amd64, arm, armel, hppa, i386, ia64, mips, powerpc, s390 and sparc architectures. The packages for the mipsel architecture will be released soon.

We recommend that you upgrade your collectd packages.");

  script_tag(name:"affected", value:"'collectd' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"collectd", ver:"4.4.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"collectd-dbg", ver:"4.4.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"collectd-dev", ver:"4.4.2-3+lenny1", rls:"DEB5"))) {
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
