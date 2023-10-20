# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841737");
  script_cve_id("CVE-2014-1690", "CVE-2014-1874", "CVE-2014-2038");
  script_tag(name:"creation_date", value:"2014-03-12 04:00:54 +0000 (Wed, 12 Mar 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  script_xref(name:"Advisory-ID", value:"USN-2140-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2140-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information leak was discovered in the Linux kernel when built with the
NetFilter Connection Tracking (NF_CONNTRACK) support for IRC protocol
(NF_NAT_IRC). A remote attacker could exploit this flaw to obtain
potentially sensitive kernel information when communicating over a client-
to-client IRC connection(/dcc) via a NAT-ed network. (CVE-2014-1690)

Matthew Thode reported a denial of service vulnerability in the Linux
kernel when SELinux support is enabled. A local user with the CAP_MAC_ADMIN
capability (and the SELinux mac_admin permission if running in enforcing
mode) could exploit this flaw to cause a denial of service (kernel crash).
(CVE-2014-1874)

An information leak was discovered in the Linux kernel's NFS filesystem. A
local users with write access to an NFS share could exploit this flaw to
obtain potential sensitive information from kernel memory. (CVE-2014-2038)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 13.10.");

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

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.11.0-18-generic", ver:"3.11.0-18.32", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.11.0-18-generic-lpae", ver:"3.11.0-18.32", rls:"UBUNTU13.10"))) {
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
