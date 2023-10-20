# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845081");
  script_cve_id("CVE-2021-34556", "CVE-2021-35477", "CVE-2021-3612", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-38160", "CVE-2021-38166", "CVE-2021-38199", "CVE-2021-38201", "CVE-2021-38202", "CVE-2021-38203", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-40490", "CVE-2021-41073");
  script_tag(name:"creation_date", value:"2021-09-30 01:00:36 +0000 (Thu, 30 Sep 2021)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-02 03:15:00 +0000 (Sat, 02 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5096-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5096-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.13' package(s) announced via the USN-5096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Valentina Palmiotti discovered that the io_uring subsystem in the Linux
kernel could be coerced to free adjacent memory. A local attacker could use
this to execute arbitrary code. (CVE-2021-41073)

Benedict Schlueter discovered that the BPF subsystem in the Linux kernel
did not properly protect against Speculative Store Bypass (SSB) side-
channel attacks in some situations. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-34556)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly protect against Speculative Store Bypass (SSB) side-channel
attacks in some situations. A local attacker could possibly use this to
expose sensitive information. (CVE-2021-35477)

Murray McAllister discovered that the joystick device interface in the
Linux kernel did not properly validate data passed via an ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code on systems with a joystick device
registered. (CVE-2021-3612)

It was discovered that the tracing subsystem in the Linux kernel did not
properly keep track of per-cpu ring buffer state. A privileged attacker
could use this to cause a denial of service. (CVE-2021-3679)

It was discovered that the Option USB High Speed Mobile device driver in
the Linux kernel did not properly handle error conditions. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2021-37159)

Alois Wohlschlager discovered that the overlay file system in the Linux
kernel did not restrict private clones in some situations. An attacker
could use this to expose sensitive information. (CVE-2021-3732)

It was discovered that the Virtio console implementation in the Linux
kernel did not properly validate input lengths in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2021-38160)

It was discovered that the BPF subsystem in the Linux kernel contained an
integer overflow in its hash table implementation. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-38166)

Michael Wakabayashi discovered that the NFSv4 client implementation in the
Linux kernel did not properly order connection setup operations. An
attacker controlling a remote NFS server could use this to cause a denial
of service on the client. (CVE-2021-38199)

It was discovered that the Sun RPC implementation in the Linux kernel
contained an out-of-bounds access error. A remote attacker could possibly
use this to cause a denial of service (system crash). (CVE-2021-38201)

It was discovered that the NFS server implementation in the Linux kernel
contained an out-of-bounds read when the trace even framework is being used
for nfsd. A remote attacker could possibly use this to cause a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-5.13' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.13.0-1014-oem", ver:"5.13.0-1014.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.13.0.1014.18", rls:"UBUNTU20.04 LTS"))) {
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
