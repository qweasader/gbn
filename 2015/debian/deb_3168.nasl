# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703168");
  script_cve_id("CVE-2012-6684");
  script_tag(name:"creation_date", value:"2015-02-21 23:00:00 +0000 (Sat, 21 Feb 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3168");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3168");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3168");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-redcloth' package(s) announced via the DSA-3168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kousuke Ebihara discovered that redcloth, a Ruby module used to convert Textile markup to HTML, did not properly sanitize its input. This allowed a remote attacker to perform a cross-site scripting attack by injecting arbitrary JavaScript code into the generated HTML.

For the stable distribution (wheezy), this problem has been fixed in version 4.2.9-2+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 4.2.9-4.

We recommend that you upgrade your ruby-redcloth packages.");

  script_tag(name:"affected", value:"'ruby-redcloth' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libredcloth-ruby", ver:"4.2.9-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libredcloth-ruby-doc", ver:"4.2.9-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libredcloth-ruby1.8", ver:"4.2.9-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libredcloth-ruby1.9.1", ver:"4.2.9-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-redcloth", ver:"4.2.9-2+deb7u2", rls:"DEB7"))) {
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
