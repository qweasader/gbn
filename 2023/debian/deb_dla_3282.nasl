# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893282");
  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_tag(name:"creation_date", value:"2023-01-27 02:00:05 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-25 14:32:00 +0000 (Wed, 25 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3282)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3282");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3282");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/git");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git' package(s) announced via the DLA-3282 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Git, a distributed revision control system. An attacker may trigger code execution in specific situations.

CVE-2022-23521

gitattributes are a mechanism to allow defining attributes for paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge number of attributes for a single pattern, or when the declared attribute names are huge. These overflows can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the index. Consequently, the failure mode depends on whether the file exists in the working tree, the index or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote code execution.

CVE-2022-41903

`git log` can display commits in an arbitrary format using its `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst` gitattribute. When processing the padding operators, there is a integer overflow in `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of files within the repository during a git archive. This integer overflow can result in arbitrary heap writes, which may result in arbitrary code execution.

For Debian 10 buster, these problems have been fixed in version 1:2.20.1-2+deb10u7.

We recommend that you upgrade your git packages.

For the detailed security status of git please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'git' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-all", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-cvs", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-daemon-run", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-daemon-sysvinit", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-doc", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-el", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-email", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-gui", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-man", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-mediawiki", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"git-svn", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gitk", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gitweb", ver:"1:2.20.1-2+deb10u7", rls:"DEB10"))) {
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
