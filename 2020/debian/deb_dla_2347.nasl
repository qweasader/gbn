# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892347");
  script_cve_id("CVE-2019-20839", "CVE-2020-14397", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");
  script_tag(name:"creation_date", value:"2020-08-29 03:00:15 +0000 (Sat, 29 Aug 2020)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-29 00:15:00 +0000 (Sat, 29 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-2347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2347");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2347");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libvncserver");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvncserver' package(s) announced via the DLA-2347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several minor vulnerabilities have been discovered in libvncserver, a server and client implementation of the VNC protocol.

CVE-2019-20839

libvncclient/sockets.c in LibVNCServer had a buffer overflow via a long socket filename.

CVE-2020-14397

libvncserver/rfbregion.c has a NULL pointer dereference.

CVE-2020-14399

Byte-aligned data was accessed through uint32_t pointers in libvncclient/rfbproto.c.

NOTE: This issue has been disputed by third parties, there is reportedly no trust boundary crossed.

CVE-2020-14400

Byte-aligned data was accessed through uint16_t pointers in libvncserver/translate.c.

NOTE: This issue has been disputed by third parties. There is no known path of exploitation or cross of a trust boundary.

CVE-2020-14401

libvncserver/scale.c had a pixel_value integer overflow.

CVE-2020-14402

libvncserver/corre.c allowed out-of-bounds access via encodings.

CVE-2020-14403

libvncserver/hextile.c allowed out-of-bounds access via encodings.

CVE-2020-14404

libvncserver/rre.c allowed out-of-bounds access via encodings.

CVE-2020-14405

libvncclient/rfbproto.c did not limit TextChat size.

For Debian 9 stretch, these problems have been fixed in version 0.9.11+dfsg-1.3~deb9u5.

We recommend that you upgrade your libvncserver packages.

For the detailed security status of libvncserver please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1", ver:"0.9.11+dfsg-1.3~deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1-dbg", ver:"0.9.11+dfsg-1.3~deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver-config", ver:"0.9.11+dfsg-1.3~deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver-dev", ver:"0.9.11+dfsg-1.3~deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1", ver:"0.9.11+dfsg-1.3~deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1-dbg", ver:"0.9.11+dfsg-1.3~deb9u5", rls:"DEB9"))) {
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
