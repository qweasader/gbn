# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5695.1");
  script_cve_id("CVE-2022-0812", "CVE-2022-1012", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-32296", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33744");
  script_tag(name:"creation_date", value:"2022-10-24 04:51:07 +0000 (Mon, 24 Oct 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:07 +0000 (Fri, 30 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-5695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5695-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5695-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp' package(s) announced via the USN-5695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SUNRPC RDMA protocol implementation in the Linux
kernel did not properly calculate the header size of a RPC message payload.
A local attacker could use this to expose sensitive information (kernel
memory). (CVE-2022-0812)

Moshe Kol, Amit Klein and Yossi Gilad discovered that the IP implementation
in the Linux kernel did not provide sufficient randomization when
calculating port offsets. An attacker could possibly use this to expose
sensitive information. (CVE-2022-1012, CVE-2022-32296)

Duoming Zhou discovered that race conditions existed in the timer handling
implementation of the Linux kernel's Rose X.25 protocol layer, resulting in
use-after-free vulnerabilities. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-2318)

Roger Pau Monne discovered that the Xen virtual block driver in the Linux
kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-26365)

Roger Pau Monne discovered that the Xen paravirtualization frontend in the
Linux kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-33740)

It was discovered that the Xen paravirtualization frontend in the Linux
kernel incorrectly shared unrelated data when communicating with certain
backends. A local attacker could use this to cause a denial of service
(guest crash) or expose sensitive information (guest kernel memory).
(CVE-2022-33741, CVE-2022-33742)

Oleksandr Tyshchenko discovered that the Xen paravirtualization platform in
the Linux kernel on ARM platforms contained a race condition in certain
situations. An attacker in a guest VM could use this to cause a denial of
service in the host OS. (CVE-2022-33744)");

  script_tag(name:"affected", value:"'linux-gcp' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1137-gcp", ver:"4.15.0-1137.153~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1137.131", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1137.131", rls:"UBUNTU16.04 LTS"))) {
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
