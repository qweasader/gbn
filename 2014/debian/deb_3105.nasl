# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703105");
  script_cve_id("CVE-2004-2771", "CVE-2014-7844");
  script_tag(name:"creation_date", value:"2014-12-15 23:00:00 +0000 (Mon, 15 Dec 2014)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 16:05:00 +0000 (Tue, 21 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3105-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3105-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3105");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heirloom-mailx' package(s) announced via the DSA-3105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security vulnerabilities were discovered in Heirloom mailx, an implementation of the mail command:

CVE-2004-2771

mailx interprets shell meta-characters in certain email addresses.

CVE-2014-7844

An unexpected feature of mailx treats syntactically valid email addresses as shell commands to execute.

Shell command execution can be re-enabled using the expandaddr option.

Note that this security update does not remove all mailx facilities for command execution, though. Scripts which send mail to addresses obtained from an untrusted source (such as a web form) should use the -- separator before the email addresses (which was fixed to work properly in this update), or they should be changed to invoke mail -t or sendmail -i -t instead, passing the recipient addresses as part of the mail header.

For the stable distribution (wheezy), these problems have been fixed in version 12.5-2+deb7u1.

We recommend that you upgrade your heirloom-mailx packages.");

  script_tag(name:"affected", value:"'heirloom-mailx' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"heirloom-mailx", ver:"12.5-2+deb7u1", rls:"DEB7"))) {
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
