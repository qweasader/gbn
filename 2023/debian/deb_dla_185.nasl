# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.185");
  script_cve_id("CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9665", "CVE-2014-9666", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9672", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-185-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-185-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-185-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DLA-185-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mateusz Jurczyk discovered multiple vulnerabilities in Freetype. Opening malformed fonts may result in denial of service or the execution of arbitrary code.

For the oldstable distribution (squeeze), these problems have been fixed in version 2.4.2-2.1+squeeze5.

For the stable distribution (wheezy), these problems were fixed in version 2.4.9-1.1+deb7u1.");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.4.2-2.1+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.4.2-2.1+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.4.2-2.1+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.4.2-2.1+squeeze5", rls:"DEB6"))) {
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
