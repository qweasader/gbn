# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893055");
  script_cve_id("CVE-2021-46790", "CVE-2022-30783", "CVE-2022-30784", "CVE-2022-30785", "CVE-2022-30786", "CVE-2022-30787", "CVE-2022-30788", "CVE-2022-30789");
  script_tag(name:"creation_date", value:"2022-06-22 01:00:15 +0000 (Wed, 22 Jun 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 18:47:00 +0000 (Wed, 28 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-3055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-3055-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3055-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ntfs-3g");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntfs-3g' package(s) announced via the DLA-3055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in NTFS-3G, a read-write NTFS driver for FUSE. A local user can take advantage of these flaws for local root privilege escalation.

CVE-2022-30783

An invalid return code in fuse_kern_mount enables intercepting of libfuse-lite protocol traffic between NTFS-3G and the kernel when using libfuse-lite.

CVE-2022-30784

A crafted NTFS image can cause heap exhaustion in ntfs_get_attribute_value.

CVE-2022-30785

A file handle created in fuse_lib_opendir, and later used in fuse_lib_readdir, enables arbitrary memory read and write operations when using libfuse-lite.

CVE-2022-30786

A crafted NTFS image can cause a heap-based buffer overflow in ntfs_names_full_collate.

CVE-2022-30787

An integer underflow in fuse_lib_readdir enables arbitrary memory read operations when using libfuse-lite.

CVE-2022-30788

A crafted NTFS image can cause a heap-based buffer overflow in ntfs_mft_rec_alloc.

CVE-2022-30789

A crafted NTFS image can cause a heap-based buffer overflow in ntfs_check_log_client_array.

For Debian 9 stretch, these problems have been fixed in version 1:2016.2.22AR.1+dfsg-1+deb9u3.

We recommend that you upgrade your ntfs-3g packages.

For the detailed security status of ntfs-3g please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libntfs-3g871", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dbg", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-udeb", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
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
