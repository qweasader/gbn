# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703086");
  script_cve_id("CVE-2014-8767", "CVE-2014-8769", "CVE-2014-9140");
  script_tag(name:"creation_date", value:"2014-12-02 23:00:00 +0000 (Tue, 02 Dec 2014)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3086");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3086");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3086");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tcpdump' package(s) announced via the DSA-3086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in tcpdump, a command-line network traffic analyzer. These vulnerabilities might result in denial of service, leaking sensitive information from memory or, potentially, execution of arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 4.3.0-1+deb7u1.

For the upcoming stable distribution (jessie), these problems have been fixed in version 4.6.2-3.

For the unstable distribution (sid), these problems have been fixed in version 4.6.2-3.

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

  if(!isnull(res = isdpkgvuln(pkg:"tcpdump", ver:"4.3.0-1+deb7u1", rls:"DEB7"))) {
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
