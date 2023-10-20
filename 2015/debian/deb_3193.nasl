# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703193");
  script_cve_id("CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155");
  script_tag(name:"creation_date", value:"2015-03-16 23:00:00 +0000 (Mon, 16 Mar 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3193");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3193");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3193");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tcpdump' package(s) announced via the DSA-3193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in tcpdump, a command-line network traffic analyzer. These vulnerabilities might result in denial of service (application crash) or, potentially, execution of arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 4.3.0-1+deb7u2.

For the upcoming stable distribution (jessie), these problems have been fixed in version 4.6.2-4.

For the unstable distribution (sid), these problems have been fixed in version 4.6.2-4.

We recommend that you upgrade your tcpdump packages.");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"tcpdump", ver:"4.3.0-1+deb7u2", rls:"DEB7"))) {
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
