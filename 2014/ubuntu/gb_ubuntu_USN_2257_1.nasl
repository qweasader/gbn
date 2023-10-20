# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841871");
  script_cve_id("CVE-2014-0178", "CVE-2014-0239", "CVE-2014-0244", "CVE-2014-3493");
  script_tag(name:"creation_date", value:"2014-07-01 16:30:30 +0000 (Tue, 01 Jul 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|13\.10|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2257-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2257-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-2257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christof Schmitt discovered that Samba incorrectly initialized a certain
response field when vfs shadow copy was enabled. A remote authenticated
attacker could use this issue to possibly obtain sensitive information.
This issue only affected Ubuntu 13.10 and Ubuntu 14.04 LTS. (CVE-2014-0178)

It was discovered that the Samba internal DNS server incorrectly handled QR
fields when processing incoming DNS messages. A remote attacker could use
this issue to cause Samba to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 14.04 LTS. (CVE-2014-0239)

Daniel Berteaud discovered that the Samba NetBIOS name service daemon
incorrectly handled certain malformed packets. A remote attacker could use
this issue to cause Samba to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 12.04 LTS, Ubuntu 13.10, and
Ubuntu 14.04 LTS. (CVE-2014-0244)

Simon Arlott discovered that Samba incorrectly handled certain unicode path
names. A remote authenticated attacker could use this issue to cause Samba
to stop responding, resulting in a denial of service. (CVE-2014-3493)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 13.10, Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:3.4.7~dfsg-1ubuntu3.15", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:3.6.3-2ubuntu2.11", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:3.6.18-1ubuntu3.3", rls:"UBUNTU13.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.1.6+dfsg-1ubuntu2.14.04.2", rls:"UBUNTU14.04 LTS"))) {
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
