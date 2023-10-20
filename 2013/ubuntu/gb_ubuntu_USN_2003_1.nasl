# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841607");
  script_cve_id("CVE-2013-4428");
  script_tag(name:"creation_date", value:"2013-10-29 11:29:11 +0000 (Tue, 29 Oct 2013)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2003-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2003-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glance' package(s) announced via the USN-2003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stuart McLaren discovered that Glance did not properly enforce the
'download_image' policy for cached images. An authenticated user could
exploit this to obtain sensitive information in an image protected by this
setting.");

  script_tag(name:"affected", value:"'glance' package(s) on Ubuntu 12.10, Ubuntu 13.04.");

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

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-glance", ver:"2012.2.4-0ubuntu1.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python-glance", ver:"1:2013.1.3-0ubuntu1.1", rls:"UBUNTU13.04"))) {
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
