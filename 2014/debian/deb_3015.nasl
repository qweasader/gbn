# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703015");
  script_cve_id("CVE-2014-5461");
  script_tag(name:"creation_date", value:"2014-08-31 22:00:00 +0000 (Sun, 31 Aug 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3015");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3015");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3015");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lua5.1' package(s) announced via the DSA-3015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based overflow vulnerability was found in the way Lua, a simple, extensible, embeddable programming language, handles varargs functions with many fixed parameters called with few arguments, leading to application crashes or, potentially, arbitrary code execution.

For the stable distribution (wheezy), this problem has been fixed in version 5.1.5-4+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 5.1.5-7.

We recommend that you upgrade your lua5.1 packages.");

  script_tag(name:"affected", value:"'lua5.1' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblua5.1-0", ver:"5.1.5-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblua5.1-0-dbg", ver:"5.1.5-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblua5.1-0-dev", ver:"5.1.5-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lua5.1", ver:"5.1.5-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lua5.1-doc", ver:"5.1.5-4+deb7u1", rls:"DEB7"))) {
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
