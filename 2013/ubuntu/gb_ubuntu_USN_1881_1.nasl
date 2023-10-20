# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841477");
  script_cve_id("CVE-2013-0160", "CVE-2013-1979", "CVE-2013-2141", "CVE-2013-2146", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2013-06-18 05:12:33 +0000 (Tue, 18 Jun 2013)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1881-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");

  script_xref(name:"Advisory-ID", value:"USN-1881-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1881-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1881-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Lutomirski discover an error in the Linux kernel's credential handling
on unix sockets. A local user could exploit this flaw to gain
administrative privileges. (CVE-2013-1979)

An information leak was discovered in the Linux kernel when inotify is used
to monitor the /dev/ptmx device. A local user could exploit this flaw to
discover keystroke timing and potentially discover sensitive information
like password length. (CVE-2013-0160)

An information leak was discovered in the Linux kernel's tkill and tgkill
system calls when used from compat processes. A local user could exploit
this flaw to examine potentially sensitive kernel memory. (CVE-2013-2141)

A flaw was discovered in the Linux kernel's perf events subsystem for Intel
Sandy Bridge and Ivy Bridge processors. A local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2013-2146)

An information leak was discovered in the Linux kernel's crypto API. A
local user could exploit this flaw to examine potentially sensitive
information from the kernel's stack memory. (CVE-2013-3076)

An information leak was discovered in the Linux kernel's rcvmsg path for
ATM (Asynchronous Transfer Mode). A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack memory.
(CVE-2013-3222)

An information leak was discovered in the Linux kernel's recvmsg path for
ax25 address family. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3223)

An information leak was discovered in the Linux kernel's recvmsg path for
the bluetooth address family. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack memory.
(CVE-2013-3224)

An information leak was discovered in the Linux kernel's bluetooth rfcomm
protocol support. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3225)

An information leak was discovered in the Linux kernel's CAIF protocol
implementation. A local user could exploit this flaw to examine potentially
sensitive information from the kernel's stack memory. (CVE-2013-3227)

An information leak was discovered in the Linux kernel's IRDA (infrared)
support subsystem. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3228)

An information leak was discovered in the Linux kernel's s390 - z/VM
support. A local user could exploit this flaw to examine potentially
sensitive information from the kernel's stack memory. (CVE-2013-3229)

An information leak was discovered in the Linux kernel's l2tp (Layer Two
Tunneling Protocol) implementation. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack memory.
(CVE-2013-3230)

An information leak was ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-34-generic", ver:"3.5.0-34.55", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-34-highbank", ver:"3.5.0-34.55", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-34-omap", ver:"3.5.0-34.55", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-34-powerpc-smp", ver:"3.5.0-34.55", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-34-powerpc64-smp", ver:"3.5.0-34.55", rls:"UBUNTU12.10"))) {
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
