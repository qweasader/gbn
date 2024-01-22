# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71473");
  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_tag(name:"creation_date", value:"2012-08-10 07:06:05 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2511-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2511-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2511-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2511");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'puppet' package(s) announced via the DSA-2511-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been found in Puppet, a centralized configuration management:

CVE-2012-3864

Authenticated clients could read arbitrary files on the puppet master.

CVE-2012-3865

Authenticated clients could delete arbitrary files on the puppet master.

CVE-2012-3866

The report of the most recent Puppet run was stored with world readable permissions, resulting in information disclosure.

CVE-2012-3867

Agent hostnames were insufficiently validated.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.2-5+squeeze6.

For the unstable distribution (sid), this problem has been fixed in version 2.7.18-1.

We recommend that you upgrade your puppet packages.");

  script_tag(name:"affected", value:"'puppet' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"puppet", ver:"2.6.2-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.2-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppet-el", ver:"2.6.2-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.6.2-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppetmaster", ver:"2.6.2-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-puppet", ver:"2.6.2-5+squeeze6", rls:"DEB6"))) {
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
