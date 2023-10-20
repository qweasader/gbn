# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705257");
  script_cve_id("CVE-2021-4037", "CVE-2022-0171", "CVE-2022-1184", "CVE-2022-20421", "CVE-2022-2602", "CVE-2022-2663", "CVE-2022-3061", "CVE-2022-3176", "CVE-2022-3303", "CVE-2022-39188", "CVE-2022-39842", "CVE-2022-40307", "CVE-2022-41674", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722");
  script_tag(name:"creation_date", value:"2022-10-20 01:00:18 +0000 (Thu, 20 Oct 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:00 +0000 (Tue, 18 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5257");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5257-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5257");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The security update announced as DSA 5257-1 caused regressions on certain systems using the amdgpu driver. Updated packages are now available to correct this issue.

For the stable distribution (bullseye), this problem has been fixed in version 5.10.149-2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-arm", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-s390", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-x86", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-4kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-5kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-686", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-686-pae", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-amd64", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-arm64", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-armmp-lpae", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-cloud-amd64", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-cloud-arm64", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-common", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-common-rt", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-loongson-3", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-marvell", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-octeon", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-powerpc64le", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-rpi", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-rt-686-pae", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-rt-amd64", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-rt-arm64", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-rt-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-19-s390x", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-loongson-3", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-marvell", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-octeon", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-4kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-4kc-malta-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-5kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-5kc-malta-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-686-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-686-pae-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-686-pae-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-686-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-amd64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-amd64-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-arm64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-arm64-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-armmp-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-armmp-lpae", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-armmp-lpae-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-cloud-amd64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-cloud-amd64-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-cloud-arm64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-cloud-arm64-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-loongson-3", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-loongson-3-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-marvell", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-marvell-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-octeon", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-octeon-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-powerpc64le", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-powerpc64le-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rpi", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rpi-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-686-pae-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-686-pae-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-amd64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-amd64-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-arm64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-arm64-unsigned", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-rt-armmp-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-s390x", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-19-s390x-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-pae-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-686-pae-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-19", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-armmp-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-marvell-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-19-4kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-19-5kc-malta-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-19-loongson-3-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-19-octeon-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-19-powerpc64le-di", ver:"5.10.149-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-19-s390x-di", ver:"5.10.149-1", rls:"DEB11"))) {
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
