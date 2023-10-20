# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703151");
  script_cve_id("CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0221");
  script_tag(name:"creation_date", value:"2015-02-02 23:00:00 +0000 (Mon, 02 Feb 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3151");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3151");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3151");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-3151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Django, a high-level Python web development framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0219

Jedediah Smith reported that the WSGI environ in Django does not distinguish between headers containing dashes and headers containing underscores. A remote attacker could use this flaw to spoof WSGI headers.

CVE-2015-0220

Mikko Ohtamaa discovered that the django.util.http.is_safe_url() function in Django does not properly handle leading whitespaces in user-supplied redirect URLs. A remote attacker could potentially use this flaw to perform a cross-site scripting attack.

CVE-2015-0221

Alex Gaynor reported a flaw in the way Django handles reading files in the django.views.static.serve() view. A remote attacker could possibly use this flaw to mount a denial of service via resource consumption.

For the stable distribution (wheezy), these problems have been fixed in version 1.4.5-1+deb7u9.

For the upcoming stable distribution (jessie), these problems have been fixed in version 1.7.1-1.1.

For the unstable distribution (sid), these problems have been fixed in version 1.7.1-1.1.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.4.5-1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.4.5-1+deb7u9", rls:"DEB7"))) {
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
