# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.450");
  script_cve_id("CVE-2015-7674", "CVE-2015-8875");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-02 17:18:15 +0000 (Thu, 02 Jun 2016)");

  script_name("Debian: Security Advisory (DLA-450-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-450-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-450-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gdk-pixbuf' package(s) announced via the DLA-450-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow has been discovered in gdk-pixbuf, a library for image loading and saving facilities, fast scaling and compositing of pixbufs, that allows remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted BMP file.

This update also fixes an incomplete patch for CVE-2015-7674.

CVE-2015-7552

Heap-based buffer overflow in the gdk_pixbuf_flip function in gdk-pixbuf-scale.c in gdk-pixbuf allows remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted BMP file.

CVE-2015-7674

Integer overflow in the pixops_scale_nearest function in pixops/pixops.c in gdk-pixbuf before 2.32.1 allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a crafted GIF image file, which triggers a heap-based buffer overflow.

For Debian 7 Wheezy, these problems have been fixed in version 2.26.1-1+deb7u4.

We recommend that you upgrade your gdk-pixbuf packages.");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gdkpixbuf-2.0", ver:"2.26.1-1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.26.1-1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0-udeb", ver:"2.26.1-1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-common", ver:"2.26.1-1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-dev", ver:"2.26.1-1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-doc", ver:"2.26.1-1+deb7u4", rls:"DEB7"))) {
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
