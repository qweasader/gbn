# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.236");
  script_cve_id("CVE-2014-9031", "CVE-2014-9033", "CVE-2014-9034", "CVE-2014-9035", "CVE-2014-9036", "CVE-2014-9037", "CVE-2014-9038", "CVE-2014-9039", "CVE-2015-3438", "CVE-2015-3439", "CVE-2015-3440");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-236)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-236");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-236");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DLA-236 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Debian squeeze-lts version of Wordpress, multiple security issues have been fixed:

Remote attackers could...

... upload files with invalid or unsafe names

... mount social engineering attacks

... compromise a site via cross-site scripting

... inject SQL commands

... cause denial of service or information disclosure

CVE-2014-9031

Jouko Pynnonen discovered an unauthenticated cross site scripting vulnerability (XSS) in wptexturize(), exploitable via comments or posts.

CVE-2014-9033

Cross site request forgery (CSRF) vulnerability in the password changing process, which could be used by an attacker to trick an user into changing her password.

CVE-2014-9034

Javier Nieto Arevalo and Andres Rojas Guerrero reported a potential denial of service in the way the phpass library is used to handle passwords, since no maximum password length was set.

CVE-2014-9035

John Blackbourn reported an XSS in the Press This function (used for quick publishing using a browser bookmarklet).

CVE-2014-9036

Robert Chapin reported an XSS in the HTML filtering of CSS in posts.

CVE-2014-9037

David Anderson reported a hash comparison vulnerability for passwords stored using the old-style MD5 scheme. While unlikely, this could be exploited to compromise an account, if the user had not logged in after a Wordpress 2.5 update (uploaded to Debian on 2 Apr, 2008) and the password MD5 hash could be collided with due to PHP dynamic comparison.

CVE-2014-9038

Ben Bidner reported a server side request forgery (SSRF) in the core HTTP layer which unsufficiently blocked the loopback IP address space.

CVE-2014-9039

Momen Bassel, Tanoy Bose, and Bojan Slavkovic reported a vulnerability in the password reset process: an email address change would not invalidate a previous password reset email.

CVE-2015-3438

Cedric Van Bockhaven reported and Gary Pendergast, Mike Adams, and Andrew Nacin of the WordPress security team fixed a cross-site-scripting vulnerabilitity, which could enable anonymous users to compromise a site.

CVE-2015-3439

Jakub Zoczek discovered a very limited cross-site scripting vulnerability, that could be used as part of a social engineering attack.

CVE-2015-3440

Jouko Pynnonen discovered a cross-site scripting vulnerability, which could enable commenters to compromise a site.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb6u6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb6u6", rls:"DEB6"))) {
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
