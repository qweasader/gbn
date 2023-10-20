# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53637");
  script_cve_id("CVE-2003-0453");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-348");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-348");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-348");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'traceroute-nanog' package(s) announced via the DSA-348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"traceroute-nanog, an enhanced version of the common traceroute program, contains an integer overflow bug which could be exploited to execute arbitrary code. traceroute-nanog is setuid root, but drops root privileges immediately after obtaining raw ICMP and raw IP sockets. Thus, exploitation of this bug provides only access to these sockets, and not root privileges.

For the stable distribution (woody) this problem has been fixed in version 6.1.1-1.3.

For the unstable distribution (sid) this problem will be fixed soon. See Debian bug #200875.

We recommend that you update your traceroute-nanog package.");

  script_tag(name:"affected", value:"'traceroute-nanog' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"traceroute-nanog", ver:"6.1.1-1.3", rls:"DEB3.0"))) {
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
