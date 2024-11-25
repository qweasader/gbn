# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.0021");
  script_cve_id("CVE-2013-7176", "CVE-2013-7177");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DLA-0021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-0021-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-0021-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fail2ban' package(s) announced via the DLA-0021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use anchored failregex for filters to avoid possible DoS. Manually picked up from the current status of 0.8 branch (as of 0.8.13-29-g09b2016): CVE-2013-7176: postfix.conf - anchored on the front, expects 'postfix/smtpd' prefix in the log line CVE-2013-7177: cyrus-imap.conf - anchored on the front, and refactored to have a single failregex couriersmtp.conf - anchored on both sides exim.conf - front-anchored versions picked up from exim.conf and exim-spam.conf lighttpd-fastcgi.conf - front-anchored picked up from suhosin.conf (copied from the Wheezy version)

Catch also failed logins via secured (imaps/pop3s) for cyrus-imap. Regression was introduced while strengthening failregex in 0.8.11 (bd175f) Debian bug #755173

cyrus-imap: catch user not found attempts

For Debian 6 Squeeze, these issues have been fixed in fail2ban version 0.8.4-3+squeeze3");

  script_tag(name:"affected", value:"'fail2ban' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fail2ban", ver:"0.8.4-3+squeeze3", rls:"DEB6"))) {
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
