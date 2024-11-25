# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3352");
  script_cve_id("CVE-2022-47664", "CVE-2022-47665", "CVE-2023-24751", "CVE-2023-24752", "CVE-2023-24754", "CVE-2023-24755", "CVE-2023-24756", "CVE-2023-24757", "CVE-2023-24758", "CVE-2023-25221");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 18:23:49 +0000 (Fri, 10 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3352-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3352-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3352-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libde265");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libde265' package(s) announced via the DLA-3352-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in libde265, an open source implementation of the h.265 video codec, which may result in denial of service, have unspecified other impact, possibly code execution due to a heap-based buffer overflow.

CVE-2022-47664

Libde265 1.0.9 is vulnerable to Buffer Overflow in ff_hevc_put_hevc_qpel_pixels_8_sse

CVE-2022-47665

Libde265 1.0.9 has a heap buffer overflow vulnerability in de265_image::set_SliceAddrRS(int, int, int)

CVE-2023-24751

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the mc_chroma function at motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-24752

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the ff_hevc_put_hevc_epel_pixels_8_sse function at sse-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-24754

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the ff_hevc_put_weighted_pred_avg_8_sse function at sse-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-24755

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the put_weighted_pred_8_fallback function at fallback-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-24756

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the ff_hevc_put_unweighted_pred_8_sse function at sse-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-24757

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the put_unweighted_pred_16_fallback function at fallback-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-24758

libde265 v1.0.10 was discovered to contain a NULL pointer dereference in the ff_hevc_put_weighted_pred_avg_8_sse function at sse-motion.cc. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input file.

CVE-2023-25221

Libde265 v1.0.10 was discovered to contain a heap-buffer-overflow vulnerability in the derive_spatial_luma_vector_prediction function in motion.cc.

For Debian 10 buster, these problems have been fixed in version 1.0.11-0+deb10u4.

We recommend that you upgrade your libde265 packages.

For the detailed security status of libde265 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libde265' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.11-0+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libde265-dev", ver:"1.0.11-0+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libde265-examples", ver:"1.0.11-0+deb10u4", rls:"DEB10"))) {
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
