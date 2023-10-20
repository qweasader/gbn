# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840695");
  script_cve_id("CVE-2011-2212", "CVE-2011-2512");
  script_tag(name:"creation_date", value:"2011-07-08 14:31:28 +0000 (Fri, 08 Jul 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1165-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1165-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the USN-1165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nelson Elhage discoverd that QEMU did not properly validate certain
virtqueue requests from the guest. An attacker could exploit this to cause
a denial of service of the guest or possibly execute code with the
privileges of the user invoking the program. (CVE-2011-2212)

Stefan Hajnoczi discovered that QEMU did not properly perform integer
comparisons when performing virtqueue input validation. An attacker could
exploit this to cause a denial of service of the guest or possibly execute
code with the privileges of the user invoking the program. (CVE-2011-2512)

When using QEMU with libvirt or virtualization management software based on
libvirt such as Eucalyptus and OpenStack, QEMU guests are individually
isolated by an AppArmor profile by default in Ubuntu.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.3+noroms-0ubuntu9.12", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.3+noroms-0ubuntu9.12", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.3+noroms-0ubuntu9.12", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.5+noroms-0ubuntu7.8", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.5+noroms-0ubuntu7.8", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.5+noroms-0ubuntu7.8", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.14.0+noroms-0ubuntu4.3", rls:"UBUNTU11.04"))) {
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
