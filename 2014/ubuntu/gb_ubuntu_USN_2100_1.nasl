# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841705");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_tag(name:"creation_date", value:"2014-02-11 05:14:51 +0000 (Tue, 11 Feb 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2100-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2100-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2100-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the USN-2100-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thijs Alkemade and Robert Vehse discovered that Pidgin incorrectly handled
the Yahoo! protocol. A remote attacker could use this issue to cause
Pidgin to crash, resulting in a denial of service. (CVE-2012-6152)

Jaime Breva Ribes discovered that Pidgin incorrectly handled the XMPP
protocol. A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service. (CVE-2013-6477)

It was discovered that Pidgin incorrectly handled long URLs. A remote
attacker could use this issue to cause Pidgin to crash, resulting in a
denial of service. (CVE-2013-6478)

Jacob Appelbaum discovered that Pidgin incorrectly handled certain HTTP
responses. A malicious remote server or a machine-in-the-middle could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-6479)

Daniel Atallah discovered that Pidgin incorrectly handled the Yahoo!
protocol. A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service. (CVE-2013-6481)

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
incorrectly handled the MSN protocol. A remote attacker could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-6482)

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
incorrectly handled XMPP iq replies. A remote attacker could use this
issue to spoof messages. (CVE-2013-6483)

It was discovered that Pidgin incorrectly handled STUN server responses. A
remote attacker could use this issue to cause Pidgin to crash, resulting in
a denial of service. (CVE-2013-6484)

Matt Jones discovered that Pidgin incorrectly handled certain chunked HTTP
responses. A malicious remote server or a machine-in-the-middle could use this
issue to cause Pidgin to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2013-6485)

Yves Younan and Ryan Pentney discovered that Pidgin incorrectly handled
certain Gadu-Gadu HTTP messages. A malicious remote server or a
machine-in-the-middle could use this issue to cause Pidgin to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2013-6487)

Yves Younan and Pawel Janic discovered that Pidgin incorrectly handled MXit
emoticons. A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2013-6489)

Yves Younan discovered that Pidgin incorrectly handled SIMPLE headers. A
remote attacker could use this issue to cause Pidgin to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2013-6490)

Daniel Atallah discovered that Pidgin incorrectly handled IRC argument
parsing. A malicious remote server or a machine-in-the-middle could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2014-0020)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.3-0ubuntu1.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.3-0ubuntu1.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.6-0ubuntu2.3", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.6-0ubuntu2.3", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.7-0ubuntu4.1.13.10.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.7-0ubuntu4.1.13.10.1", rls:"UBUNTU13.10"))) {
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
