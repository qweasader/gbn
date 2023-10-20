# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69731");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2235");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2235");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2235");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Icedove, an unbranded version of the Thunderbird mail/news client.

CVE-2011-0069

CVE-2011-0070

CVE-2011-0072

CVE-2011-0074

CVE-2011-0075

CVE-2011-0077

CVE-2011-0078

CVE-2011-0080

CVE-2011-0081

Scoobidiver, Ian Beer Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren, Jesse Ruderman, Aki Kelin and Martin Barbella discovered memory corruption bugs, which may lead to the execution of arbitrary code.

CVE-2011-0065

CVE-2011-0066

CVE-2011-0073

regenrecht discovered several dangling pointer vulnerabilities, which may lead to the execution of arbitrary code.

CVE-2011-0067

Paul Stone discovered that Java applets could steal information from the autocompletion history.

CVE-2011-0071

Soroush Dalili discovered a directory traversal vulnerability in handling resource URIs.

As indicated in the Lenny (oldstable) release notes, security support for the Icedove packages in the oldstable needed to be stopped before the end of the regular Lenny security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a different mail client.

For the stable distribution (squeeze), this problem has been fixed in version 3.0.11-1+squeeze2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze2", rls:"DEB6"))) {
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
