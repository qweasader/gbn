# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.293.1");
  script_cve_id("CVE-2006-2452");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-293-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-293-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm' package(s) announced via the USN-293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"If the admin configured a gdm theme that provided an user list, any
user could activate the gdm setup program by first choosing the setup
option from the menu, clicking on the user list and entering his own
(instead of root's) password. This allowed normal users to configure
potentially dangerous features like remote or automatic login.

Please note that this does not affect a default Ubuntu installation,
since the default theme does not provide an user list. In Ubuntu 6.06
you additionally have to have the 'ConfigAvailable' setting enabled in
gdm.conf to be vulnerable (it is disabled by default).

Ubuntu 5.04 is not affected by this flaw.");

  script_tag(name:"affected", value:"'gdm' package(s) on Ubuntu 5.10, Ubuntu 6.06.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gdm", ver:"2.8.0.5-0ubuntu1.2", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gdm", ver:"2.14.6-0ubuntu2.1", rls:"UBUNTU6.06 LTS"))) {
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
