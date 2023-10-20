# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704867");
  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"creation_date", value:"2021-03-03 04:00:20 +0000 (Wed, 03 Mar 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");

  script_name("Debian: Security Advisory (DSA-4867)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4867");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4867");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4867");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021-GRUB-UEFI-SecureBoot");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/grub2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'grub2' package(s) announced via the DSA-4867 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the GRUB2 bootloader.

CVE-2020-14372

It was discovered that the acpi command allows a privileged user to load crafted ACPI tables when Secure Boot is enabled.

CVE-2020-25632

A use-after-free vulnerability was found in the rmmod command.

CVE-2020-25647

An out-of-bound write vulnerability was found in the grub_usb_device_initialize() function, which is called to handle USB device initialization.

CVE-2020-27749

A stack buffer overflow flaw was found in grub_parser_split_cmdline.

CVE-2020-27779

It was discovered that the cutmem command allows a privileged user to remove memory regions when Secure Boot is enabled.

CVE-2021-20225

A heap out-of-bounds write vulnerability was found in the short form option parser.

CVE-2021-20233

A heap out-of-bound write flaw was found caused by mis-calculation of space required for quoting in the menu rendering.

Further detailed information can be found at [link moved to references]

For the stable distribution (buster), these problems have been fixed in version 2.02+dfsg1-20+deb10u4.

We recommend that you upgrade your grub2 packages.

For the detailed security status of grub2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'grub2' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-common", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-coreboot", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-coreboot-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-coreboot-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed-template", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed-template", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-signed-template", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-emu", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-emu-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-firmware-qemu", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-ieee1275", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-ieee1275-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-ieee1275-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-linuxbios", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-mount-udeb", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-pc", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-pc-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-pc-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-rescue-pc", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-theme-starfield", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-uboot", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-uboot-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-uboot-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen-host", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-yeeloong", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-yeeloong-bin", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-yeeloong-dbg", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub2", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub2-common", ver:"2.02+dfsg1-20+deb10u4", rls:"DEB10"))) {
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
