# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704416");
  script_cve_id("CVE-2019-5716", "CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719", "CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214");
  script_tag(name:"creation_date", value:"2019-03-23 22:00:00 +0000 (Sat, 23 Mar 2019)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 18:29:00 +0000 (Thu, 16 May 2019)");

  script_name("Debian: Security Advisory (DSA-4416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4416-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4416-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4416");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wireshark");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-4416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Wireshark, a network traffic analyzer, contained several vulnerabilities in the dissectors for 6LoWPAN, P_MUL, RTSE, ISAKMP, TCAP, ASN.1 BER and RPCAP, which could result in denial of service.

For the stable distribution (stretch), these problems have been fixed in version 2.6.7-1~deb9u1.

We recommend that you upgrade your wireshark packages.

For the detailed security status of wireshark please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark-data", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark-dev", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark11", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwiretap-dev", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwiretap8", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwscodecs2", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwsutil-dev", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwsutil9", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-doc", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.7-1~deb9u1", rls:"DEB9"))) {
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
