# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702592");
  script_cve_id("CVE-2012-4545");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2592)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2592");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2592");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2592");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'elinks' package(s) announced via the DSA-2592 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marko Myllynen discovered that ELinks, a powerful text-mode browser, incorrectly delegates user credentials during GSS-Negotiate.

For the stable distribution (squeeze), this problem has been fixed in version 0.12~pre5-2+squeeze1. Since the initial Squeeze release, XULRunner needed to be updated and the version currently in the archive is incompatible with ELinks. As such, JavaScript support needed to be disabled (only a small subset of typical functionality was supported anyway). It will likely be re-enabled in a later point update.

For the testing distribution (wheezy), this problem has been fixed in version 0.12~pre5-9.

For the unstable distribution (sid), this problem has been fixed in version 0.12~pre5-9.

We recommend that you upgrade your elinks packages.");

  script_tag(name:"affected", value:"'elinks' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"elinks", ver:"0.12~pre5-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"elinks-data", ver:"0.12~pre5-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"elinks-doc", ver:"0.12~pre5-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"elinks-lite", ver:"0.12~pre5-2+squeeze1", rls:"DEB6"))) {
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
