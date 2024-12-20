# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842563");
  script_tag(name:"creation_date", value:"2015-12-17 04:09:00 +0000 (Thu, 17 Dec 2015)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2839-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2839-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2839-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1505328");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-2839-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"As a security improvement against the POODLE attack, this update disables
SSLv3 support in the CUPS web interface.

For legacy environments where SSLv3 support is still required, it can be
re-enabled by adding 'SSLOptions AllowSSL3' to /etc/cups/cupsd.conf.");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"1.7.2-0ubuntu1.7", rls:"UBUNTU14.04 LTS"))) {
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
