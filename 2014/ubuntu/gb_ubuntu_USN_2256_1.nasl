# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841872");
  script_cve_id("CVE-2014-3497");
  script_tag(name:"creation_date", value:"2014-07-01 16:39:12 +0000 (Tue, 01 Jul 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2256-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2256-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2256-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'swift' package(s) announced via the USN-2256-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"John Dickinson discovered that Swift did not properly quote the
WWW-Authenticate header value. If a user were tricked into navigating to a
malicious Swift URL, an attacker could conduct cross-site scripting
attacks. With cross-site scripting vulnerabilities, if a user were tricked
into viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal confidential
data, within the same domain.");

  script_tag(name:"affected", value:"'swift' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-swift", ver:"1.13.1-0ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
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
