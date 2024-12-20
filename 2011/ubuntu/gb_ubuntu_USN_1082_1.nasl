# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840602");
  script_cve_id("CVE-2010-0421", "CVE-2011-0020", "CVE-2011-0064");
  script_tag(name:"creation_date", value:"2011-03-07 05:45:55 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1082-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1082-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pango1.0' package(s) announced via the USN-1082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marc Schoenefeld discovered that Pango incorrectly handled certain Glyph
Definition (GDEF) tables. If a user were tricked into displaying text with
a specially-crafted font, an attacker could cause Pango to crash, resulting
in a denial of service. This issue only affected Ubuntu 8.04 LTS and 9.10.
(CVE-2010-0421)

Dan Rosenberg discovered that Pango incorrectly handled certain FT_Bitmap
objects. If a user were tricked into displaying text with a specially-
crafted font, an attacker could cause a denial of service or execute
arbitrary code with privileges of the user invoking the program. The
default compiler options for affected releases should reduce the
vulnerability to a denial of service. (CVE-2011-0020)

It was discovered that Pango incorrectly handled certain memory
reallocation failures. If a user were tricked into displaying text in a way
that would cause a reallocation failure, an attacker could cause a denial
of service or execute arbitrary code with privileges of the user invoking
the program. This issue only affected Ubuntu 9.10, 10.04 LTS and 10.10.
(CVE-2011-0064)");

  script_tag(name:"affected", value:"'pango1.0' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gir1.0-pango-1.0", ver:"1.28.0-0ubuntu2.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gir1.0-pango-1.0", ver:"1.28.2-0ubuntu1.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.20.5-0ubuntu1.2", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.26.0-1ubuntu0.1", rls:"UBUNTU9.10"))) {
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
