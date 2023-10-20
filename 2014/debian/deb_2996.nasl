# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702996");
  script_cve_id("CVE-2014-1544", "CVE-2014-1547", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557");
  script_tag(name:"creation_date", value:"2014-08-02 22:00:00 +0000 (Sat, 02 Aug 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2996)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2996");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2996");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2996");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2996 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Icedove, Debian's version of the Mozilla Thunderbird mail and news client: Multiple memory safety errors and use-after-frees may lead to the execution of arbitrary code or denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 24.7.0-1~deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"calendar-google-provider", ver:"24.7.0-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"24.7.0-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"24.7.0-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"24.7.0-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-extension", ver:"24.7.0-1~deb7u1", rls:"DEB7"))) {
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
