# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891730");
  script_cve_id("CVE-2019-13115", "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2019-03-25 22:00:00 +0000 (Mon, 25 Mar 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 14:10:46 +0000 (Tue, 26 Mar 2019)");

  script_name("Debian: Security Advisory (DLA-1730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1730-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1730-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh2' package(s) announced via the DLA-1730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have recently been discovered in libssh2, a client-side C library implementing the SSH2 protocol

CVE-2019-3855

An integer overflow flaw which could have lead to an out of bounds write was discovered in libssh2 in the way packets were read from the server. A remote attacker who compromised an SSH server could have been able to execute code on the client system when a user connected to the server.

CVE-2019-3856

An integer overflow flaw, which could have lead to an out of bounds write, was discovered in libssh2 in the way keyboard prompt requests were parsed. A remote attacker who compromised an SSH server could have been able to execute code on the client system when a user connected to the server.

CVE-2019-3857

An integer overflow flaw which could have lead to an out of bounds write was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit signal were parsed. A remote attacker who compromises an SSH server could have been able to execute code on the client system when a user connected to the server.

CVE-2019-3858

An out of bounds read flaw was discovered in libssh2 when a specially crafted SFTP packet was received from the server. A remote attacker who compromised an SSH server could have been able to cause a Denial of Service or read data in the client memory.

CVE-2019-3859

An out of bounds read flaw was discovered in libssh2's _libssh2_packet_require and _libssh2_packet_requirev functions. A remote attacker who compromised an SSH server could have be able to cause a Denial of Service or read data in the client memory.

CVE-2019-3860

An out of bounds read flaw was discovered in libssh2 in the way SFTP packets with empty payloads were parsed. A remote attacker who compromised an SSH server could have be able to cause a Denial of Service or read data in the client memory.

CVE-2019-3861

An out of bounds read flaw was discovered in libssh2 in the way SSH packets with a padding length value greater than the packet length were parsed. A remote attacker who compromised a SSH server could have been able to cause a Denial of Service or read data in the client memory.

CVE-2019-3862

An out of bounds read flaw was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit status message and no payload were parsed. A remote attacker who compromised an SSH server could have been able to cause a Denial of Service or read data in the client memory.

CVE-2019-3863

A server could have sent multiple keyboard interactive response messages whose total length were greater than unsigned char max characters. This value was used as an index to copy memory causing an out of bounds memory write error.

For Debian 8 Jessie, these problems have been fixed in version 1.4.3-4.1+deb8u2.

We recommend that you upgrade your libssh2 packages.

Further information about Debian LTS security advisories, how to apply these ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libssh2' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1", ver:"1.4.3-4.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dbg", ver:"1.4.3-4.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dev", ver:"1.4.3-4.1+deb8u2", rls:"DEB8"))) {
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
