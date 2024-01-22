# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891261");
  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-6418", "CVE-2017-6420");
  script_tag(name:"creation_date", value:"2018-01-30 23:00:00 +0000 (Tue, 30 Jan 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)");

  script_name("Debian: Security Advisory (DLA-1261-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1261-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1261-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DLA-1261-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in clamav, the ClamAV AntiVirus toolkit for Unix. Effects range from denial of service to potential arbitrary code execution. Additionally, this version fixes a longstanding issue that has recently resurfaced whereby a malformed virus signature database can cause an application crash and denial of service.

CVE-2017-12374

ClamAV has a use-after-free condition arising from a lack of input validation. A remote attacker could exploit this vulnerability with a crafted email message to cause a denial of service.

CVE-2017-12375

ClamAV has a buffer overflow vulnerability arising from a lack of input validation. An unauthenticated remote attacker could send a crafted email message to the affected device, triggering a buffer overflow and potentially a denial of service when the malicious message is scanned.

CVE-2017-12376

ClamAV has a buffer overflow vulnerability arising from improper input validation when handling Portable Document Format (PDF) files. An unauthenticated remote attacker could send a crafted PDF file to the affected device, triggering a buffer overflow and potentially a denial of service or arbitrary code execution when the malicious file is scanned.

CVE-2017-12377

ClamAV has a heap overflow vulnerability arising from improper input validation when handling mew packets. An attacker could exploit this by sending a crafted message to the affected device, triggering a denial of service or possible arbitrary code execution when the malicious file is scanned.

CVE-2017-12378

ClamAV has a buffer overread vulnerability arising from improper input validation when handling tape archive (TAR) files. An unauthenticated remote attacker could send a crafted TAR file to the affected device, triggering a buffer overread and potentially a denial of service when the malicious file is scanned.

CVE-2017-12379

ClamAV has a buffer overflow vulnerability arising from improper input validation in the message parsing function. An unauthenticated remote attacker could send a crafted email message to the affected device, triggering a buffer overflow and potentially a denial of service or arbitrary code execution when the malicious message is scanned.

CVE-2017-12380

ClamAV has a NULL dereference vulnerability arising from improper input validation in the message parsing function. An unauthenticated remote attacker could send a crafted email message to the affected device, triggering a NULL pointer dereference, which may result in a denial of service.

Debian Bug #824196 A malformed virus signature database could cause an application crash and denial of service.

For Debian 7 Wheezy, these problems have been fixed in version 0.99.2+dfsg-0+deb7u4.

We recommend that you upgrade your clamav packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav7", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7"))) {
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
