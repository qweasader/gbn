# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841644");
  script_cve_id("CVE-2013-4299", "CVE-2013-4470", "CVE-2014-1444", "CVE-2014-1445");
  script_tag(name:"creation_date", value:"2013-12-04 04:55:35 +0000 (Wed, 04 Dec 2013)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2040-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2040-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-quantal' package(s) announced via the USN-2040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Linux kernel's dm snapshot facility. A remote
authenticated user could exploit this flaw to obtain sensitive information
or modify/corrupt data. (CVE-2013-4299)

Hannes Frederic Sowa discovered a flaw in the Linux kernel's UDP
Fragmentation Offload (UFO). An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2013-4470)

An information leak was discovered in the Linux kernel's SIOCWANDEV ioctl
call. A local user with the CAP_NET_ADMIN capability could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-1444)

An information leak was discovered in the wanxl ioctl function the Linux
kernel. A local user could exploit this flaw to obtain potentially
sensitive information from kernel memory. (CVE-2014-1445)");

  script_tag(name:"affected", value:"'linux-lts-quantal' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-44-generic", ver:"3.5.0-44.67~precise1", rls:"UBUNTU12.04 LTS"))) {
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
