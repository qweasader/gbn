# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2016.014.01");
  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Slackware: Security Advisory (SSA:2016-014-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.0|13\.1|13\.37|14\.0|14\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2016-014-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.677958");
  script_xref(name:"URL", value:"http://www.openssh.com/legacy.html");
  script_xref(name:"URL", value:"https://www.qualys.com/2016/01/14/cve-2016-0777-cve-2016-0778/openssh-cve-2016-0777-cve-2016-0778.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SSA:2016-014-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssh packages are available for Slackware 13.0, 13.1, 13.37, 14.0, 14.1,
and -current to fix security issues.


Here are the details from the Slackware 14.1 ChangeLog:
+--------------------------+
patches/packages/openssh-7.1p2-i486-1_slack14.1.txz: Upgraded.
 This update fixes an information leak and a buffer overflow. In particular,
 the information leak allows a malicious SSH server to steal the client's
 private keys. Thanks to Qualys for reporting this issue.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 *****************************************************************
 * IMPORTANT: READ BELOW ABOUT POTENTIALLY INCOMPATIBLE CHANGES *
 *****************************************************************
 Rather than backport the fix for the information leak (which is the only
 hazardous flaw), we have upgraded to the latest OpenSSH. As of version
 7.0, OpenSSH has deprecated some older (and presumably less secure)
 algorithms, and also (by default) only allows root login by public-key,
 hostbased and GSSAPI authentication. Make sure that your keys and
 authentication method will allow you to continue accessing your system
 after the upgrade.
 The release notes for OpenSSH 7.0 list the following incompatible changes
 to be aware of:
 * Support for the legacy SSH version 1 protocol is disabled by
 default at compile time.
 * Support for the 1024-bit diffie-hellman-group1-sha1 key exchange
 is disabled by default at run-time. It may be re-enabled using
 the instructions at [link moved to references]
 * Support for ssh-dss, ssh-dss-cert-* host and user keys is disabled
 by default at run-time. These may be re-enabled using the
 instructions at [link moved to references]
 * Support for the legacy v00 cert format has been removed.
 * The default for the sshd_config(5) PermitRootLogin option has
 changed from 'yes' to 'prohibit-password'.
 * PermitRootLogin=without-password/prohibit-password now bans all
 interactive authentication methods, allowing only public-key,
 hostbased and GSSAPI authentication (previously it permitted
 keyboard-interactive and password-less authentication if those
 were enabled).
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'openssh' package(s) on Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK13.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-x86_64-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-x86_64-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.37") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-i486-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-x86_64-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-i486-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-x86_64-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-i486-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-x86_64-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"7.1p2-x86_64-1", rls:"SLKcurrent"))) {
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
