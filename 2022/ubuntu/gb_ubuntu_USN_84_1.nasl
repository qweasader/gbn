# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.84.1");
  script_cve_id("CVE-2005-0194", "CVE-2005-0446");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-84-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-84-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-84-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the USN-84-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When parsing the configuration file, squid interpreted empty Access
Control Lists (ACLs) without defined authentication schemes in a
non-obvious way. This could allow remote attackers to bypass intended
ACLs. (CAN-2005-0194)

A remote Denial of Service vulnerability was discovered in the domain
name resolution code. A faulty or malicious DNS server could stop the
Squid server immediately by sending a malformed IP address.
(CAN-2005-0446)");

  script_tag(name:"affected", value:"'squid' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"2.5.5-6ubuntu0.5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"2.5.5-6ubuntu0.5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"2.5.5-6ubuntu0.5", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"2.5.5-6ubuntu0.5", rls:"UBUNTU4.10"))) {
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
