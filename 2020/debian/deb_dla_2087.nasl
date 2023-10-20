# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892087");
  script_cve_id("CVE-2019-18625", "CVE-2019-18792");
  script_tag(name:"creation_date", value:"2020-01-31 04:00:08 +0000 (Fri, 31 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 20:19:00 +0000 (Thu, 29 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2087)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2087");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2087");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'suricata' package(s) announced via the DLA-2087 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have recently been discovered in the stream-tcp code of the intrusion detection and prevention tool Suricata.

CVE-2019-18625

It was possible to bypass/evade any tcp based signature by faking a closed TCP session using an evil server. After the TCP SYN packet, it was possible to inject a RST ACK and a FIN ACK packet with a bad TCP Timestamp option. The client would have ignored the RST ACK and the FIN ACK packets because of the bad TCP Timestamp option.

CVE-2019-18792

It was possible to bypass/evade any tcp based signature by overlapping a TCP segment with a fake FIN packet. The fake FIN packet had to be injected just before the PUSH ACK packet we wanted to bypass. The PUSH ACK packet (containing the data) would have been ignored by Suricata because it would have overlapped the FIN packet (the sequence and ack number are identical in the two packets). The client would have ignored the fake FIN packet because the ACK flag would not have been set.

For Debian 8 Jessie, these problems have been fixed in version 2.0.7-2+deb8u5.

We recommend that you upgrade your suricata packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'suricata' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"suricata", ver:"2.0.7-2+deb8u5", rls:"DEB8"))) {
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
