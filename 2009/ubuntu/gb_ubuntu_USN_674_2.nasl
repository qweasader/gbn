# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840211");
  script_cve_id("CVE-2008-2940", "CVE-2008-2941");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-674-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU7\.10");

  script_xref(name:"Advisory-ID", value:"USN-674-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-674-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the USN-674-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-674-1 provided packages to fix vulnerabilities in HPLIP. Due to an
internal archive problem, the updates for Ubuntu 7.10 would not install
properly. This update provides fixed packages for Ubuntu 7.10.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the hpssd tool of hplip did not validate
 privileges in the alert-mailing function. A local attacker could
 exploit this to gain privileges and send e-mail messages from the
 account of the hplip user. This update alters hplip behaviour by
 preventing users from setting alerts and by moving alert configuration
 to a root-controlled /etc/hp/alerts.conf file. (CVE-2008-2940)

 It was discovered that the hpssd tool of hplip did not correctly
 handle certain commands. A local attacker could use a specially
 crafted packet to crash hpssd, leading to a denial of service.
 (CVE-2008-2941)");

  script_tag(name:"affected", value:"'hplip' package(s) on Ubuntu 7.10.");

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

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"hplip", ver:"2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10"))) {
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
