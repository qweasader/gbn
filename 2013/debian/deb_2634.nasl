# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702634");
  script_cve_id("CVE-2012-4520", "CVE-2013-0305", "CVE-2013-0306", "CVE-2013-1665");
  script_tag(name:"creation_date", value:"2013-02-26 23:00:00 +0000 (Tue, 26 Feb 2013)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2634-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2634-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2634-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2634");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-2634-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Django, a high-level Python web development framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-4520

James Kettle discovered that Django did not properly filter the HTTP Host header when processing certain requests. An attacker could exploit this to generate and cause parts of Django, particularly the password-reset mechanism, to display arbitrary URLs to users.

CVE-2013-0305

Orange Tsai discovered that the bundled administrative interface of Django could expose supposedly-hidden information via its history log.

CVE-2013-0306

Mozilla discovered that an attacker can abuse Django's tracking of the number of forms in a formset to cause a denial-of-service attack due to extreme memory consumption.

CVE-2013-1665

Michael Koziarski discovered that Django's XML deserialization is vulnerable to entity-expansion and external-entity/DTD attacks.

For the stable distribution (squeeze), these problems have been fixed in version 1.2.3-3+squeeze5.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.4.4-1.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze5", rls:"DEB6"))) {
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
