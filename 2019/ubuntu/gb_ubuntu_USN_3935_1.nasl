# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843963");
  script_cve_id("CVE-2011-5325", "CVE-2014-9645", "CVE-2015-9261", "CVE-2016-2147", "CVE-2016-2148", "CVE-2017-15873", "CVE-2017-16544", "CVE-2018-1000517", "CVE-2018-20679", "CVE-2019-5747");
  script_tag(name:"creation_date", value:"2019-04-04 02:03:26 +0000 (Thu, 04 Apr 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-30 17:21:26 +0000 (Thu, 30 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3935-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3935-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3935-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the USN-3935-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tyler Hicks discovered that BusyBox incorrectly handled symlinks inside tar
archives. If a user or automated system were tricked into processing a
specially crafted tar archive, a remote attacker could overwrite arbitrary
files outside of the current directory. This issue only affected Ubuntu
14.04 LTS and Ubuntu 16.04 LTS. (CVE-2011-5325)

Mathias Krause discovered that BusyBox incorrectly handled kernel module
loading restrictions. A local attacker could possibly use this issue to
bypass intended restrictions. This issue only affected Ubuntu 14.04 LTS.
(CVE-2014-9645)

It was discovered that BusyBox incorrectly handled certain ZIP archives. If
a user or automated system were tricked into processing a specially crafted
ZIP archive, a remote attacker could cause BusyBox to crash, leading to a
denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2015-9261)

Nico Golde discovered that the BusyBox DHCP client incorrectly handled
certain malformed domain names. A remote attacker could possibly use this
issue to cause the DHCP client to crash, leading to a denial of service.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-2147)

Nico Golde discovered that the BusyBox DHCP client incorrectly handled
certain 6RD options. A remote attacker could use this issue to cause the
DHCP client to crash, leading to a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04
LTS. (CVE-2016-2148)

It was discovered that BusyBox incorrectly handled certain bzip2 archives.
If a user or automated system were tricked into processing a specially
crafted bzip2 archive, a remote attacker could cause BusyBox to crash,
leading to a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-15873)

It was discovered that BusyBox incorrectly handled tab completion. A local
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-16544)

It was discovered that the BusyBox wget utility incorrectly handled certain
responses. A remote attacker could use this issue to cause BusyBox to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2018-1000517)

It was discovered that the BusyBox DHCP utilities incorrectly handled
certain memory operations. A remote attacker could possibly use this issue
to access sensitive information. (CVE-2018-20679, CVE-2019-5747)");

  script_tag(name:"affected", value:"'busybox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.21.0-1ubuntu1.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.21.0-1ubuntu1.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.21.0-1ubuntu1.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpc", ver:"1:1.21.0-1ubuntu1.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpd", ver:"1:1.21.0-1ubuntu1.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.22.0-15ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.22.0-15ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.22.0-15ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpc", ver:"1:1.22.0-15ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpd", ver:"1:1.22.0-15ubuntu1.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.27.2-2ubuntu3.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.27.2-2ubuntu3.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.27.2-2ubuntu3.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpc", ver:"1:1.27.2-2ubuntu3.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpd", ver:"1:1.27.2-2ubuntu3.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.27.2-2ubuntu4.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.27.2-2ubuntu4.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.27.2-2ubuntu4.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpc", ver:"1:1.27.2-2ubuntu4.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udhcpd", ver:"1:1.27.2-2ubuntu4.1", rls:"UBUNTU18.10"))) {
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
