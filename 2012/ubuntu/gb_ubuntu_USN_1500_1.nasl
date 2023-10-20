# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841076");
  script_cve_id("CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603", "CVE-2011-4922", "CVE-2011-4939", "CVE-2012-1178", "CVE-2012-2214", "CVE-2012-2318", "CVE-2012-3374");
  script_tag(name:"creation_date", value:"2012-07-10 04:38:13 +0000 (Tue, 10 Jul 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1500-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1500-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1500-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the USN-1500-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evgeny Boger discovered that Pidgin incorrectly handled buddy list messages in
the AIM and ICQ protocol handlers. A remote attacker could send a specially
crafted message and cause Pidgin to crash, leading to a denial of service. This
issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10. (CVE-2011-4601)

Thijs Alkemade discovered that Pidgin incorrectly handled malformed voice and
video chat requests in the XMPP protocol handler. A remote attacker could send
a specially crafted message and cause Pidgin to crash, leading to a denial of
service. This issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10.
(CVE-2011-4602)

Diego Bauche Madero discovered that Pidgin incorrectly handled UTF-8
sequences in the SILC protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a denial
of service. This issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10.
(CVE-2011-4603)

Julia Lawall discovered that Pidgin incorrectly cleared memory contents used in
cryptographic operations. An attacker could exploit this to read the memory
contents, leading to an information disclosure. This issue only affected Ubuntu
10.04 LTS. (CVE-2011-4922)

Clemens Huebner and Kevin Strange discovered that Pidgin incorrectly handled
nickname changes inside chat rooms in the XMPP protocol handler. A remote
attacker could exploit this by changing nicknames, leading to a denial of
service. This issue only affected Ubuntu 11.10. (CVE-2011-4939)

Thijs Alkemade discovered that Pidgin incorrectly handled off-line instant
messages in the MSN protocol handler. A remote attacker could send a specially
crafted message and cause Pidgin to crash, leading to a denial of service. This
issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10. (CVE-2012-1178)

Jose Valentin Gutierrez discovered that Pidgin incorrectly handled SOCKS5 proxy
connections during file transfer requests in the XMPP protocol handler. A
remote attacker could send a specially crafted request and cause Pidgin to
crash, leading to a denial of service. This issue only affected Ubuntu 12.04
LTS and 11.10. (CVE-2012-2214)

Fabian Yamaguchi discovered that Pidgin incorrectly handled malformed messages
in the MSN protocol handler. A remote attacker could send a specially crafted
message and cause Pidgin to crash, leading to a denial of service.
(CVE-2012-2318)

Ulf Harnhammar discovered that Pidgin incorrectly handled messages with in-line
images in the MXit protocol handler. A remote attacker could send a specially
crafted message and possibly execute arbitrary code with user privileges.
(CVE-2012-3374)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"1:2.6.6-1ubuntu4.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.6.6-1ubuntu4.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.6.6-1ubuntu4.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"1:2.7.11-1ubuntu2.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.7.11-1ubuntu2.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.7.11-1ubuntu2.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"1:2.10.0-0ubuntu2.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.0-0ubuntu2.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.0-0ubuntu2.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"1:2.10.3-0ubuntu1.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.3-0ubuntu1.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.3-0ubuntu1.1", rls:"UBUNTU12.04 LTS"))) {
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
