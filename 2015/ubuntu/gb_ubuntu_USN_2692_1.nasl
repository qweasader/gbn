# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842387");
  script_cve_id("CVE-2015-3214", "CVE-2015-5154", "CVE-2015-5158");
  script_tag(name:"creation_date", value:"2015-07-30 03:13:10 +0000 (Thu, 30 Jul 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:54:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-2692-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2692-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2692-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-2692-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Tait discovered that QEMU incorrectly handled PIT emulation. In a
non-default configuration, a malicious guest could use this issue to cause
a denial of service, or possibly execute arbitrary code on the host as the
user running the QEMU process. In the default installation, when QEMU is
used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2015-3214)

Kevin Wolf discovered that QEMU incorrectly handled processing ATAPI
commands. A malicious guest could use this issue to cause a denial of
service, or possibly execute arbitrary code on the host as the user running
the QEMU process. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2015-5154)

Zhu Donghai discovered that QEMU incorrectly handled the SCSI driver. A
malicious guest could use this issue to cause a denial of service, or
possibly execute arbitrary code on the host as the user running the QEMU
process. In the default installation, when QEMU is used with libvirt,
attackers would be isolated by the libvirt AppArmor profile. This issue
only affected Ubuntu 15.04. (CVE-2015-5158)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 15.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.15", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.2+dfsg-5expubuntu9.3", rls:"UBUNTU15.04"))) {
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
