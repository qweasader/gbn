# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2014.2444.1");
  script_cve_id("CVE-2014-7825", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8884");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-11-10 14:47:00 +0000 (Mon, 10 Nov 2014)");

  script_name("Ubuntu: Security Advisory (USN-2444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2444-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2444-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-2444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rabin Vincent, Robert Swiecki, Russell King discovered that the ftrace
subsystem of the Linux kernel does not properly handle private syscall
numbers. A local user could exploit this flaw to cause a denial of service
(OOPS). (CVE-2014-7826)

Rabin Vincent, Robert Swiecki, Russell Kinglaw discovered a flaw in how the
perf subsystem of the Linux kernel handles private systecall numbers. A
local user could exploit this to cause a denial of service (OOPS) or bypass
ASLR protections via a crafted application. (CVE-2014-7825)

A null pointer dereference flaw was discovered in the Linux kernel's
SCTP implementation when ASCONF is used. A remote attacker could exploit
this flaw to cause a denial of service (system crash) via a malformed INIT
chunk. (CVE-2014-7841)

A stack buffer overflow was discovered in the ioctl command handling for
the Technotrend/Hauppauge USB DEC devices driver. A local user could
exploit this flaw to cause a denial of service (system crash) or possibly
gain privileges. (CVE-2014-8884)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-1457-omap4", ver:"3.2.0-1457.77", rls:"UBUNTU12.04 LTS"))) {
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
