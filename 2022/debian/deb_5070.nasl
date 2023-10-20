# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705070");
  script_cve_id("CVE-2021-4122");
  script_tag(name:"creation_date", value:"2022-02-17 07:17:20 +0000 (Thu, 17 Feb 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 14:28:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5070");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5070");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5070");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cryptsetup");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cryptsetup' package(s) announced via the DSA-5070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-4122

Milan Broz, its maintainer, discovered an issue in cryptsetup, the disk encryption configuration tool for Linux.

LUKS2 (an on-disk format) online reencryption is an optional extension to allow a user to change the data reencryption key while the data device is available for use during the whole reencryption process.

An attacker can modify on-disk metadata to simulate decryption in progress with crashed (unfinished) reencryption step and persistently decrypt part of the LUKS2 device (LUKS1 devices are indirectly affected as well, see below).

This attack requires repeated physical access to the LUKS2 device but no knowledge of user passphrases.

The decryption step is performed after a valid user activates the device with a correct passphrase and modified metadata.

The size of possible decrypted data per attack step depends on configured LUKS2 header size (metadata size is configurable for LUKS2). With the default LUKS2 parameters (16 MiB header) and only one allocated keyslot (512 bit key for AES-XTS), simulated decryption with checksum resilience SHA1 (20 bytes checksum for 4096-byte blocks), the maximal decrypted size can be over 3GiB.

The attack is not applicable to LUKS1 format, but the attacker can update metadata in place to LUKS2 format as an additional step. For such a converted LUKS2 header, the keyslot area is limited to decrypted size (with SHA1 checksums) over 300 MiB.

LUKS devices that were formatted using a cryptsetup binary from Debian Stretch or earlier are using LUKS1. However since Debian Buster the default on-disk LUKS format version is LUKS2. In particular, encrypted devices formatted by the Debian Buster and Bullseye installers are using LUKS2 by default.

Key truncation in dm-integrity This update additionally fixes a key truncation issue for standalone dm-integrity devices using HMAC integrity protection. For existing such devices with extra long HMAC keys (typically >106 bytes of length), one might need to manually truncate the key using integritysetup(8)'s --integrity-key-size option in order to properly map the device under 2:2.3.7-1+deb11u1 and later. Only standalone dm-integrity devices are affected. dm-crypt devices, including those using authenticated disk encryption, are unaffected.

For the oldstable distribution (buster), this problem is not present.

For the stable distribution (bullseye), this problem has been fixed in version 2:2.3.7-1+deb11u1.

We recommend that you upgrade your cryptsetup packages.

For the detailed security status of cryptsetup please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cryptsetup' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cryptsetup", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cryptsetup-bin", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cryptsetup-initramfs", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cryptsetup-run", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cryptsetup-udeb", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcryptsetup-dev", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcryptsetup12", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcryptsetup12-udeb", ver:"2:2.3.7-1+deb11u1", rls:"DEB11"))) {
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
