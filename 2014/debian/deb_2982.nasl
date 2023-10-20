# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702982");
  script_cve_id("CVE-2014-3482", "CVE-2014-3483");
  script_tag(name:"creation_date", value:"2014-07-18 22:00:00 +0000 (Fri, 18 Jul 2014)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2982)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2982");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2982");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2982");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-activerecord-3.2' package(s) announced via the DSA-2982 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sean Griffin discovered two vulnerabilities in the PostgreSQL adapter for Active Record which could lead to SQL injection.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.6-5+deb7u1. Debian provides two variants of Ruby on Rails in Wheezy (2.3 and 3.2). Support for the 2.3 variants had to be ceased at this point. This affects the following source packages: ruby-actionmailer-2.3, ruby-actionpack-2.3, ruby-activerecord-2.3, ruby-activeresource-2.3, ruby-activesupport-2.3 and ruby-rails-2.3. The version of Redmine in Wheezy still requires 2.3, you can use an updated version from backports.debian.org which is compatible with rails 3.2.

For the unstable distribution (sid), these problems have been fixed in version 3.2.19-1 of the rails-3.2 source package.

We recommend that you upgrade your ruby-activerecord-3.2 packages.");

  script_tag(name:"affected", value:"'ruby-activerecord-3.2' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-activerecord-3.2", ver:"3.2.6-5+deb7u1", rls:"DEB7"))) {
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
