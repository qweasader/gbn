# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705324");
  script_cve_id("CVE-2022-2873", "CVE-2022-3545", "CVE-2022-3623", "CVE-2022-36280", "CVE-2022-41218", "CVE-2022-45934", "CVE-2022-4696", "CVE-2022-47929", "CVE-2023-0179", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-01-25 02:00:27 +0000 (Wed, 25 Jan 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-5324)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5324");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5324");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5324");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5324 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2022-2873

Zheyu Ma discovered that an out-of-bounds memory access flaw in the Intel iSMT SMBus 2.0 host controller driver may result in denial of service (system crash).

CVE-2022-3545

It was discovered that the Netronome Flow Processor (NFP) driver contained a use-after-free flaw in area_cache_get(), which may result in denial of service or the execution of arbitrary code.

CVE-2022-3623

A race condition when looking up a CONT-PTE/PMD size hugetlb page may result in denial of service or an information leak.

CVE-2022-4696

A use-after-free vulnerability was discovered in the io_uring subsystem.

CVE-2022-36280

An out-of-bounds memory write vulnerability was discovered in the vmwgfx driver, which may allow a local unprivileged user to cause a denial of service (system crash).

CVE-2022-41218

Hyunwoo Kim reported a use-after-free flaw in the Media DVB core subsystem caused by refcount races, which may allow a local user to cause a denial of service or escalate privileges.

CVE-2022-45934

An integer overflow in l2cap_config_req() in the Bluetooth subsystem was discovered, which may allow a physically proximate attacker to cause a denial of service (system crash).

CVE-2022-47929

Frederick Lawler reported a NULL pointer dereference in the traffic control subsystem allowing an unprivileged user to cause a denial of service by setting up a specially crafted traffic control configuration.

CVE-2023-0179

Davide Ornaghi discovered incorrect arithmetic when fetching VLAN header bits in the netfilter subsystem, allowing a local user to leak stack and heap addresses or potentially local privilege escalation to root.

CVE-2023-0266

A use-after-free flaw in the sound subsystem due to missing locking may result in denial of service or privilege escalation.

CVE-2023-0394

Kyle Zeng discovered a NULL pointer dereference flaw in rawv6_push_pending_frames() in the network subsystem allowing a local user to cause a denial of service (system crash).

CVE-2023-23454

Kyle Zeng reported that the Class Based Queueing (CBQ) network scheduler was prone to denial of service due to interpreting classification results before checking the classification return code.

CVE-2023-23455

Kyle Zeng reported that the ATM Virtual Circuits (ATM) network scheduler was prone to a denial of service due to interpreting classification results before checking the classification return code.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.162-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-arm", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-s390", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-x86", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-4kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-5kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-686", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-686-pae", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-amd64", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-arm64", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-armmp-lpae", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-cloud-amd64", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-cloud-arm64", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-common", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-common-rt", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-loongson-3", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-marvell", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-octeon", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-powerpc64le", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-rpi", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-rt-686-pae", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-rt-amd64", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-rt-arm64", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-rt-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-21-s390x", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-loongson-3", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-marvell", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-octeon", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-4kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-4kc-malta-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-5kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-5kc-malta-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-686-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-686-pae-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-686-pae-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-686-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-amd64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-amd64-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-arm64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-arm64-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-armmp-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-armmp-lpae", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-armmp-lpae-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-cloud-amd64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-cloud-amd64-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-cloud-arm64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-cloud-arm64-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-loongson-3", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-loongson-3-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-marvell", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-marvell-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-octeon", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-octeon-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-powerpc64le", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-powerpc64le-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rpi", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rpi-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-686-pae-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-686-pae-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-amd64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-amd64-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-arm64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-arm64-unsigned", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-rt-armmp-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-s390x", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-21-s390x-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-pae-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-686-pae-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-21", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-armmp-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-marvell-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-21-4kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-21-5kc-malta-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-21-loongson-3-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-21-octeon-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-21-powerpc64le-di", ver:"5.10.162-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-21-s390x-di", ver:"5.10.162-1", rls:"DEB11"))) {
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
