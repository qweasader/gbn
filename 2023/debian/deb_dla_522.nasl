# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.522");
  script_cve_id("CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-522)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-522");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-522");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python2.7' package(s) announced via the DLA-522 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-0772

A vulnerability in smtplib allowing MITM attacker to perform a startTLS stripping attack. smtplib does not seem to raise an exception when the remote end (smtp server) is capable of negotiating starttls but fails to respond with 220 (ok) to an explicit call of SMTP.starttls(). This may allow a malicious MITM to perform a startTLS stripping attack if the client code does not explicitly check the response code for startTLS.

CVE-2016-5636

Issue #26171: Fix possible integer overflow and heap corruption in zipimporter.get_data().

CVE-2016-5699

Protocol injection can occur not only if an application sets a header based on user-supplied values, but also if the application ever tries to fetch a URL specified by an attacker (SSRF case) OR if the application ever accesses any malicious web server (redirection case).

For Debian 7 Wheezy, these problems have been fixed in version 2.7.3-6+deb7u3.

We recommend that you upgrade your python2.7 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python2.7' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.7", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-dbg", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-dev", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-doc", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-examples", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.3-6+deb7u3", rls:"DEB7"))) {
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
