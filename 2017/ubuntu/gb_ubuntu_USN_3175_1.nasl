# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843028");
  script_cve_id("CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388", "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5393", "CVE-2017-5396");
  script_tag(name:"creation_date", value:"2017-01-28 04:41:32 +0000 (Sat, 28 Jan 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:54:49 +0000 (Thu, 02 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3175-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3175-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3175-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3175-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2017-5373, CVE-2017-5374)

JIT code allocation can allow a bypass of ASLR protections in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2017-5375)

Nicolas Gregoire discovered a use-after-free when manipulating XSL in
XSLT documents in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2017-5376)

Atte Kettunen discovered a memory corruption issue in Skia in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2017-5377)

Jann Horn discovered that an object's address could be discovered through
hashed codes of JavaScript objects shared between pages. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to obtain sensitive information. (CVE-2017-5378)

A use-after-free was discovered in Web Animations in some circumstances.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2017-5379)

A use-after-free was discovered during DOM manipulation of SVG content in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2017-5380)

Jann Horn discovered that the 'export' function in the Certificate Viewer
can force local filesystem navigation when the Common Name contains
slashes. If a user were tricked in to exporting a specially crafted
certificate, an attacker could potentially exploit this to save content
with arbitrary filenames in unsafe locations. (CVE-2017-5381)

Jerri Rice discovered that the Feed preview for RSS feeds can be used to
capture errors and exceptions generated by privileged content. An attacker
could potentially exploit this to obtain sensitive information.
(CVE-2017-5382)

Armin Razmjou discovered that certain unicode glyphs do not trigger
punycode display. An attacker could potentially exploit this to spoof the
URL bar contents. (CVE-2017-5383)

Paul Stone and Alex Chapman discovered that the full URL path is exposed
to JavaScript functions specified by Proxy Auto-Config (PAC) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"51.0.1+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"51.0.1+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"51.0.1+build2-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"51.0.1+build2-0ubuntu0.16.10.1", rls:"UBUNTU16.10"))) {
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
