# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893221");
  script_cve_id("CVE-2018-16472", "CVE-2021-23518");
  script_tag(name:"creation_date", value:"2022-12-05 02:00:13 +0000 (Mon, 05 Dec 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 19:27:00 +0000 (Thu, 27 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-3221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3221");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3221");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-cached-path-relative");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-cached-path-relative' package(s) announced via the DLA-3221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cristian-Alexandru Staicu discovered a prototype pollution vulnerability in inode-cached-path-relative, a Node.js module used to cache (memoize) the result of path.relative.

CVE-2018-16472

An attacker controlling both the path and the cached value, can mount a prototype pollution attack and thus overwrite arbitrary properties on Object.prototype, which may result in denial of service.

CVE-2021-23518

The fix for CVE-2018-16472 was incomplete and other prototype pollution vulnerabilities were found in the meantime, resulting in a new CVE.

For Debian 10 buster, these problems have been fixed in version 1.0.1-2+deb10u1.

We recommend that you upgrade your node-cached-path-relative packages.

For the detailed security status of node-cached-path-relative please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-cached-path-relative' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-cached-path-relative", ver:"1.0.1-2+deb10u1", rls:"DEB10"))) {
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
