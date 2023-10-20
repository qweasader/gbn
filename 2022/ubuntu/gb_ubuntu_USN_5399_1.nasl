# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845350");
  script_cve_id("CVE-2020-25637", "CVE-2021-3631", "CVE-2021-3667", "CVE-2021-3975", "CVE-2021-4147", "CVE-2022-0897");
  script_tag(name:"creation_date", value:"2022-05-03 01:00:24 +0000 (Tue, 03 May 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-5399-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5399-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5399-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-5399-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvirt incorrectly handled certain locking
operations. A local attacker could possibly use this issue to cause libvirt
to stop accepting connections, resulting in a denial of service. This issue
only affected Ubuntu 20.04 LTS. (CVE-2021-3667)

It was discovered that libvirt incorrectly handled threads during shutdown.
A local attacker could possibly use this issue to cause libvirt to crash,
resulting in a denial of service. This issue only affected Ubuntu 18.04 LTS
and Ubuntu 20.04 LTS. (CVE-2021-3975)

It was discovered that libvirt incorrectly handled the libxl driver. An
attacker inside a guest could possibly use this issue to cause libvirtd
to crash or stop responding, resulting in a denial of service. This issue
only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.10.
(CVE-2021-4147)

It was discovered that libvirt incorrectly handled the nwfilter driver. A
local attacker could possibly use this issue to cause libvirt to crash,
resulting in a denial of service. (CVE-2022-0897)

It was discovered that libvirt incorrectly handled the polkit access
control driver. A local attacker could possibly use this issue to cause
libvirt to crash, resulting in a denial of service. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-25637)

It was discovered that libvirt incorrectly generated SELinux labels. In
environments using SELinux, this issue could allow the sVirt confinement
to be bypassed. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04
LTS. (CVE-2021-3631)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"4.0.0-1ubuntu8.21", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"4.0.0-1ubuntu8.21", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"4.0.0-1ubuntu8.21", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"6.0.0-0ubuntu8.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"6.0.0-0ubuntu8.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"6.0.0-0ubuntu8.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"7.6.0-0ubuntu1.2", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"7.6.0-0ubuntu1.2", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"7.6.0-0ubuntu1.2", rls:"UBUNTU21.10"))) {
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
