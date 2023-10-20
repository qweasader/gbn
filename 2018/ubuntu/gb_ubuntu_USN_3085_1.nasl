# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843778");
  script_cve_id("CVE-2015-7552", "CVE-2015-8875", "CVE-2016-6352");
  script_tag(name:"creation_date", value:"2018-10-26 04:18:27 +0000 (Fri, 26 Oct 2018)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3085-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3085-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf' package(s) announced via the USN-3085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GDK-PixBuf library did not properly handle specially
crafted bmp images, leading to a heap-based buffer overflow. If a user or
automated system were tricked into opening a specially crafted bmp file, a
remote attacker could use this flaw to cause GDK-PixBuf to crash, resulting
in a denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-7552)

It was discovered that the GDK-PixBuf library contained an integer overflow
when handling certain images. If a user or automated system were tricked into
opening a crafted image file, a remote attacker could use this flaw to cause
GDK-PixBuf to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8875)

Franco Costantini discovered that the GDK-PixBuf library contained an
out-of-bounds write error when parsing an ico file. If a user or automated
system were tricked into opening a crafted ico file, a remote attacker could
use this flaw to cause GDK-PixBuf to crash, resulting in a denial of service.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6352)");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.26.1-1ubuntu1.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.30.7-0ubuntu1.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.32.2-1ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
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
