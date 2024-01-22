# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702598");
  script_cve_id("CVE-2011-1428", "CVE-2012-5534");
  script_tag(name:"creation_date", value:"2013-01-04 23:00:00 +0000 (Fri, 04 Jan 2013)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2598-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2598-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2598");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'weechat' package(s) announced via the DSA-2598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been discovered in WeeChat, a fast, light and extensible chat client:

CVE-2011-1428

X.509 certificates were incorrectly validated.

CVE-2012-5534

The hook_process function in the plugin API allowed the execution of arbitrary shell commands.

For the stable distribution (squeeze), these problems have been fixed in version 0.3.2-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in version 0.3.8-1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 0.3.9.2-1.

We recommend that you upgrade your weechat packages.");

  script_tag(name:"affected", value:"'weechat' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"weechat", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"weechat-core", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"weechat-curses", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"weechat-dbg", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"weechat-dev", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"weechat-doc", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"weechat-plugins", ver:"0.3.2-1+squeeze1", rls:"DEB6"))) {
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
