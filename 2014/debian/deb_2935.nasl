# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702935");
  script_cve_id("CVE-2014-3775");
  script_tag(name:"creation_date", value:"2014-05-20 22:00:00 +0000 (Tue, 20 May 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2935)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2935");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2935");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2935");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgadu' package(s) announced via the DSA-2935 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that malformed responses from a Gadu-Gadu file relay server could lead to denial of service or the execution of arbitrary code in applications linked to the libgadu library.

The oldstable distribution (squeeze) is not affected.

For the stable distribution (wheezy), this problem has been fixed in version 1.11.2-1+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 1:1.12.0~rc3-1.

We recommend that you upgrade your libgadu packages.");

  script_tag(name:"affected", value:"'libgadu' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-dev", ver:"1:1.11.2-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-doc", ver:"1:1.11.2-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3", ver:"1:1.11.2-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3-dbg", ver:"1:1.11.2-1+deb7u2", rls:"DEB7"))) {
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
