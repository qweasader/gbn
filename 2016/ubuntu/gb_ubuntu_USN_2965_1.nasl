# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842762");
  script_cve_id("CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3672", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-4557");
  script_tag(name:"creation_date", value:"2016-05-17 14:25:21 +0000 (Tue, 17 May 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 20:31:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-2965-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2965-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2965-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2965-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the extended Berkeley Packet Filter (eBPF)
implementation in the Linux kernel did not properly reference count file
descriptors, leading to a use-after-free. A local unprivileged attacker
could use this to gain administrative privileges. (CVE-2016-4557)

Ralf Spenneberg discovered that the USB sound subsystem in the Linux kernel
did not properly validate USB device descriptors. An attacker with physical
access could use this to cause a denial of service (system crash).
(CVE-2016-2184)

Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in the
Linux kernel did not properly validate USB device descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2185)

Ralf Spenneberg discovered that the PowerMate USB driver in the Linux
kernel did not properly validate USB device descriptors. An attacker with
physical access could use this to cause a denial of service (system crash).
(CVE-2016-2186)

Ralf Spenneberg discovered that the I/O-Warrior USB device driver in the
Linux kernel did not properly validate USB device descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2188)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
MCT USB RS232 Converter device driver in the Linux kernel did not properly
validate USB device descriptors. An attacker with physical access could use
this to cause a denial of service (system crash). (CVE-2016-3136)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
Cypress M8 USB device driver in the Linux kernel did not properly validate
USB device descriptors. An attacker with physical access could use this to
cause a denial of service (system crash). (CVE-2016-3137)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
USB abstract device control driver for modems and ISDN adapters did not
validate endpoint descriptors. An attacker with physical access could use
this to cause a denial of service (system crash). (CVE-2016-3138)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
Linux kernel's USB driver for Digi AccelePort serial converters did not
properly validate USB device descriptors. An attacker with physical access
could use this to cause a denial of service (system crash). (CVE-2016-3140)

It was discovered that the IPv4 implementation in the Linux kernel did not
perform the destruction of inet device objects properly. An attacker in a
guest OS could use this to cause a denial of service (networking outage) in
the host OS. (CVE-2016-3156)

Andy Lutomirski discovered that the Linux kernel did not properly context-
switch IOPL on 64-bit PV Xen guests. An attacker in a guest OS could use
this to cause a denial of service (guest OS crash), gain privileges, or
obtain sensitive information. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-generic", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-generic-lpae", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-lowlatency", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc-e500mc", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc-smp", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc64-emb", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc64-smp", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS"))) {
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
