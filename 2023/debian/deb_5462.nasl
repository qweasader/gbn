# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5462");
  script_cve_id("CVE-2023-20593");
  script_tag(name:"creation_date", value:"2023-07-31 04:22:04 +0000 (Mon, 31 Jul 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:29:00 +0000 (Tue, 01 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5462");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5462");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5462");
  script_xref(name:"URL", value:"https://lock.cmpxchg8b.com/zenbleed.html");
  script_xref(name:"URL", value:"https://github.com/google/security-research/security/advisories/GHSA-v6wh-rxpg-cmm8");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5462 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that under specific microarchitectural circumstances, a vector register in AMD Zen 2 CPUs may not be written to 0 correctly. This flaw allows an attacker to leak sensitive information across concurrent processes, hyper threads and virtualized guests.

For details please refer to [link moved to references] and [link moved to references]

This issue can also be mitigated by a microcode update through the amd64-microcode package or a system firmware (BIOS/UEFI) update. However, the initial microcode release by AMD only provides updates for second generation EPYC CPUs. Various Ryzen CPUs are also affected, but no updates are available yet.

For the stable distribution (bookworm), this problem has been fixed in version 6.1.38-2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"7.1.0+6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-12-arm", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-12-s390", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-12-x86", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-4kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-5kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-686", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-686-pae", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-amd64", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-arm64", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-armmp-lpae", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-cloud-amd64", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-cloud-arm64", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-common", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-common-rt", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-loongson-3", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-marvell", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-mips32r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-mips64r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-octeon", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-powerpc64le", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-rpi", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-rt-686-pae", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-rt-amd64", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-rt-arm64", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-rt-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-10-s390x", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-loongson-3", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-marvell", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-mips32r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-mips64r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-octeon", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-4kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-4kc-malta-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-5kc-malta", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-5kc-malta-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-686-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-686-pae-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-686-pae-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-686-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-amd64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-amd64-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-arm64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-arm64-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-armmp-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-armmp-lpae", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-armmp-lpae-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-cloud-amd64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-cloud-amd64-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-cloud-arm64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-cloud-arm64-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-loongson-3", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-loongson-3-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-marvell", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-marvell-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-mips32r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-mips32r2el-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-mips64r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-mips64r2el-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-octeon", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-octeon-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-powerpc64le", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-powerpc64le-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rpi", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rpi-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-686-pae-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-686-pae-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-amd64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-amd64-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-arm64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-arm64-unsigned", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-rt-armmp-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-s390x", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-10-s390x-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-pae-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips32r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips32r2el-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips64r2el", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips64r2el-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-686-pae-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-10", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtla", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-armmp-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-marvell-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-4kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-5kc-malta-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-loongson-3-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-mips32r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-mips64r2el-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-octeon-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-powerpc64le-di", ver:"6.1.38-2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-10-s390x-di", ver:"6.1.38-2", rls:"DEB12"))) {
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
