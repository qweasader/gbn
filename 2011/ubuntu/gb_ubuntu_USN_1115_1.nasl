# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840641");
  script_cve_id("CVE-2011-0729", "CVE-2011-1842");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1115-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");

  script_xref(name:"Advisory-ID", value:"USN-1115-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1115-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'language-selector' package(s) announced via the USN-1115-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Romain Perier discovered that the language-selector D-Bus backend did not
correctly check for Policy Kit authorizations. A local attacker could exploit
this to inject shell commands into the system-wide locale configuration file,
leading to root privilege escalation.");

  script_tag(name:"affected", value:"'language-selector' package(s) on Ubuntu 10.10.");

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

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"language-selector-common", ver:"0.6.7", rls:"UBUNTU10.10"))) {
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
