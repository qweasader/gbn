# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703383");
  script_cve_id("CVE-2015-2213", "CVE-2015-5622", "CVE-2015-5714", "CVE-2015-5715", "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5734", "CVE-2015-7989");
  script_tag(name:"creation_date", value:"2015-10-28 23:00:00 +0000 (Wed, 28 Oct 2015)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3383-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3383-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3383");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-3383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Wordpress, a web blogging tool. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-2213

SQL Injection allowed a remote attacker to compromise the site.

CVE-2015-5622

The robustness of the shortcodes HTML tags filter has been improved. The parsing is a bit more strict, which may affect your installation.

CVE-2015-5714

A cross-site scripting vulnerability when processing shortcode tags.

CVE-2015-5715

A vulnerability has been discovered, allowing users without proper permissions to publish private posts and make them sticky.

CVE-2015-5731

An attacker could lock a post that was being edited.

CVE-2015-5732

Cross-site scripting in a widget title allows an attacker to steal sensitive information.

CVE-2015-5734

Fix some broken links in the legacy theme preview.

CVE-2015-7989

A cross-site scripting vulnerability in user list tables.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.6.1+dfsg-1~deb7u8.

For the stable distribution (jessie), these problems have been fixed in version 4.1+dfsg-1+deb8u5 or earlier in DSA-3332-1 and DSA-3375-1.

For the testing distribution (stretch), these problems have been fixed in version 4.3.1+dfsg-1 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in version 4.3.1+dfsg-1 or earlier versions.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u8", rls:"DEB7"))) {
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
