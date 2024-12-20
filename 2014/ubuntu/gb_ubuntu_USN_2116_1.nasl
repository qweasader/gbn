# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841716");
  script_cve_id("CVE-2013-2929", "CVE-2013-4592", "CVE-2013-6378", "CVE-2013-6380");
  script_tag(name:"creation_date", value:"2014-02-20 09:46:12 +0000 (Thu, 20 Feb 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  script_xref(name:"Advisory-ID", value:"USN-2116-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2116-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-2116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vasily Kulikov reported a flaw in the Linux kernel's implementation of
ptrace. An unprivileged local user could exploit this flaw to obtain
sensitive information from kernel memory. (CVE-2013-2929)

A flaw in the handling of memory regions of the kernel virtual machine
(KVM) subsystem was discovered. A local user with the ability to assign a
device could exploit this flaw to cause a denial of service (memory
consumption). (CVE-2013-4592)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
debugfs filesystem. An administrative local user could exploit this flaw to
cause a denial of service (OOPS). (CVE-2013-6378)

Nico Golde and Fabian Yamaguchi reported a flaw in the driver for Adaptec
AACRAID scsi raid devices in the Linux kernel. A local user could use this
flaw to cause a denial of service or possibly other unspecified impact.
(CVE-2013-6380)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 13.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-238-omap4", ver:"3.5.0-238.54", rls:"UBUNTU13.10"))) {
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
