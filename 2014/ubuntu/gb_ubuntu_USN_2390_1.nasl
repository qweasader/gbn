# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842015");
  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698");
  script_tag(name:"creation_date", value:"2014-10-29 04:53:47 +0000 (Wed, 29 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2390-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2390-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the USN-2390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jacob Appelbaum and an anonymous person discovered that Pidgin incorrectly
handled certificate validation. A remote attacker could exploit this to
perform a machine-in-the-middle attack to view sensitive information or alter
encrypted communications. (CVE-2014-3694)

Yves Younan and Richard Johnson discovered that Pidgin incorrectly handled
certain malformed MXit emoticons. A malicious remote server or a
machine-in-the-middle could use this issue to cause Pidgin to crash,
resulting in a denial of service. (CVE-2014-3695)

Yves Younan and Richard Johnson discovered that Pidgin incorrectly handled
certain malformed Groupwise messages. A malicious remote server or a
machine-in-the-middle could use this issue to cause Pidgin to crash,
resulting in a denial of service. (CVE-2014-3696)

Thijs Alkemade and Paul Aurich discovered that Pidgin incorrectly handled
memory when processing XMPP messages. A malicious remote server or user
could use this issue to cause Pidgin to disclosure arbitrary memory,
resulting in an information leak. (CVE-2014-3698)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.3-0ubuntu1.6", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.3-0ubuntu1.6", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.9-0ubuntu3.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.9-0ubuntu3.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"1:2.10.9-0ubuntu7.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.10.9-0ubuntu7.1", rls:"UBUNTU14.10"))) {
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
