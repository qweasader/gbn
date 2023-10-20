# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5884.1");
  script_cve_id("CVE-2021-4155", "CVE-2022-20566", "CVE-2022-41858", "CVE-2022-42895", "CVE-2023-0045", "CVE-2023-23559");
  script_tag(name:"creation_date", value:"2023-02-24 04:10:38 +0000 (Fri, 24 Feb 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 19:29:00 +0000 (Mon, 23 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5884-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5884-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-5884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kirill Tkhai discovered that the XFS file system implementation in the
Linux kernel did not calculate size correctly when pre-allocating space in
some situations. A local attacker could use this to expose sensitive
information. (CVE-2021-4155)

Lee Jones discovered that a use-after-free vulnerability existed in the
Bluetooth implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-20566)

Duoming Zhou discovered that a race condition existed in the SLIP driver in
the Linux kernel, leading to a null pointer dereference vulnerability. An
attacker could use this to cause a denial of service (system crash).
(CVE-2022-41858)

Tamas Koczka discovered that the Bluetooth L2CAP implementation in the
Linux kernel did not properly initialize memory in some situations. A
physically proximate attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2022-42895)

Jose Oliveira and Rodrigo Branco discovered that the prctl syscall
implementation in the Linux kernel did not properly protect against
indirect branch prediction attacks in some situations. A local attacker
could possibly use this to expose sensitive information. (CVE-2023-0045)

It was discovered that the RNDIS USB driver in the Linux kernel contained
an integer overflow vulnerability. A local attacker with physical access
could plug in a malicious USB device to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2023-23559)");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1154-aws", ver:"4.4.0-1154.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1154.158", rls:"UBUNTU16.04 LTS"))) {
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
