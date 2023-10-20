# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840744");
  script_cve_id("CVE-2010-3859", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4251", "CVE-2010-4526", "CVE-2010-4649", "CVE-2010-4668", "CVE-2010-4805", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1020", "CVE-2011-1044", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1478", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1598", "CVE-2011-1770", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2918", "CVE-2011-3637", "CVE-2011-4913", "CVE-2011-4914");
  script_tag(name:"creation_date", value:"2011-09-16 15:22:17 +0000 (Fri, 16 Sep 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:07:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1204-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1204-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fsl-imx51' package(s) announced via the USN-1204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Dan Rosenberg discovered that multiple terminal ioctls did not correctly
initialize structure memory. A local attacker could exploit this to read
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2010-4075, CVE-2010-4076, CVE-2010-4077)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)

Dan Rosenberg discovered that certain iovec operations did not calculate
page counts correctly. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
iov segments. A local attacker with access to a SCSI device could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2010-4163, CVE-2010-4668)

Dan Rosenberg discovered that the RDS protocol did not correctly check
ioctl arguments. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4175)

Alan Cox discovered that the HCI UART driver did not correctly check if a
write operation was available. If the mmap_min-addr sysctl was changed from
the Ubuntu default to a value of 0, a local attacker could exploit this
flaw to gain root privileges. (CVE-2010-4242)

Brad Spengler discovered that the kernel did not correctly account for
userspace memory allocations during exec() calls. A local attacker could
exploit this to consume all system memory, leading to a denial of service.
(CVE-2010-4243)

Alex Shi and Eric Dumazet discovered that the network stack did not
correctly handle packet backlogs. A remote attacker could exploit this by
sending a large amount of network traffic to cause the system to run out of
memory, leading to a denial of service. (CVE-2010-4251, CVE-2010-4805)

It was discovered that the ICMP stack did not correctly handle certain
unreachable messages. If a remote attacker were able to acquire a socket
lock, they could send specially crafted traffic that would crash the
system, leading to a denial of service. (CVE-2010-4526)

Dan Carpenter discovered that the Infiniband driver did not correctly
handle certain requests. A local user could exploit this to crash the
system or potentially gain root privileges. (CVE-2010-4649, CVE-2011-1044)

Kees Cook reported that /proc/pid/stat did not correctly filter certain
memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-fsl-imx51' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-610-imx51", ver:"2.6.31-610.28", rls:"UBUNTU10.04 LTS"))) {
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
