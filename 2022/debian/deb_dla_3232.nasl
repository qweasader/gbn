# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893232");
  script_cve_id("CVE-2019-18388", "CVE-2019-18389", "CVE-2019-18390", "CVE-2019-18391", "CVE-2020-8002", "CVE-2020-8003", "CVE-2022-0135");
  script_tag(name:"creation_date", value:"2022-12-08 02:00:23 +0000 (Thu, 08 Dec 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 17:10:00 +0000 (Wed, 31 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3232");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3232");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/virglrenderer");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virglrenderer' package(s) announced via the DLA-3232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in virglrenderer, a virtual GPU for KVM virtualization.

CVE-2019-18388

A NULL pointer dereference in vrend_renderer.c in virglrenderer through 0.8.0 allows guest OS users to cause a denial of service via malformed commands.

CVE-2019-18389

A heap-based buffer overflow in the vrend_renderer_transfer_write_iov function in vrend_renderer.c in virglrenderer through 0.8.0 allows guest OS users to cause a denial of service, or QEMU guest-to-host escape and code execution, via VIRGL_CCMD_RESOURCE_INLINE_WRITE commands.

CVE-2019-18390

An out-of-bounds read in the vrend_blit_need_swizzle function in vrend_renderer.c in virglrenderer through 0.8.0 allows guest OS users to cause a denial of service via VIRGL_CCMD_BLIT commands.

CVE-2019-18391

A heap-based buffer overflow in the vrend_renderer_transfer_write_iov function in vrend_renderer.c in virglrenderer through 0.8.0 allows guest OS users to cause a denial of service via VIRGL_CCMD_RESOURCE_INLINE_WRITE commands.

CVE-2020-8002

A NULL pointer dereference in vrend_renderer.c in virglrenderer through 0.8.1 allows attackers to cause a denial of service via commands that attempt to launch a grid without previously providing a Compute Shader (CS).

CVE-2020-8003

A double-free vulnerability in vrend_renderer.c in virglrenderer through 0.8.1 allows attackers to cause a denial of service by triggering texture allocation failure, because vrend_renderer_resource_allocated_texture is not an appropriate place for a free.

CVE-2022-0135

An out-of-bounds write issue was found in the VirGL virtual OpenGL renderer (virglrenderer). This flaw allows a malicious guest to create a specially crafted virgil resource and then issue a VIRTGPU_EXECBUFFER ioctl, leading to a denial of service or possible code execution.

For Debian 10 buster, these problems have been fixed in version 0.7.0-2+deb10u1.

We recommend that you upgrade your virglrenderer packages.

For the detailed security status of virglrenderer please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'virglrenderer' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvirglrenderer-dev", ver:"0.7.0-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirglrenderer0", ver:"0.7.0-2+deb10u1", rls:"DEB10"))) {
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
