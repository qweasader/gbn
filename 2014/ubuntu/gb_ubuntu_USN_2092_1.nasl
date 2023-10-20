# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841701");
  script_cve_id("CVE-2013-4344", "CVE-2013-4375", "CVE-2013-4377");
  script_tag(name:"creation_date", value:"2014-02-03 08:40:54 +0000 (Mon, 03 Feb 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2092-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2092-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asias He discovered that QEMU incorrectly handled SCSI controllers with
more than 256 attached devices. A local user could possibly use this flaw
to elevate privileges. (CVE-2013-4344)

It was discovered that QEMU incorrectly handled Xen disks. A local guest
could possibly use this flaw to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4375)

Sibiao Luo discovered that QEMU incorrectly handled device hot-unplugging.
A local user could possibly use this flaw to cause a denial of service.
This issue only affected Ubuntu 13.10. (CVE-2013-4377)");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.0+noroms-0ubuntu14.13", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.2.0+noroms-0ubuntu2.12.10.6", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10"))) {
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
