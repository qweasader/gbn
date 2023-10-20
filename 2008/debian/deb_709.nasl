# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53534");
  script_cve_id("CVE-2005-0664");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-709)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-709");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-709");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-709");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libexif' package(s) announced via the DSA-709 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sylvain Defresne discovered a buffer overflow in libexif, a library that parses EXIF files (such as JPEG files with extra tags). This bug could be exploited to crash the application and maybe to execute arbitrary code as well.

For the stable distribution (woody) this problem has been fixed in version 0.5.0-1woody1.

For the unstable distribution (sid) this problem has been fixed in version 0.6.9-5.

We recommend that you upgrade your libexif package.");

  script_tag(name:"affected", value:"'libexif' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libexif-dev", ver:"0.5.0-1woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexif5", ver:"0.5.0-1woody1", rls:"DEB3.0"))) {
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
