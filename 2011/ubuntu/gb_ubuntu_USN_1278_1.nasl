# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840819");
  script_cve_id("CVE-2011-1585", "CVE-2011-2183", "CVE-2011-2491", "CVE-2011-2496", "CVE-2011-2517");
  script_tag(name:"creation_date", value:"2011-11-25 06:33:26 +0000 (Fri, 25 Nov 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1278-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1278-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-maverick' package(s) announced via the USN-1278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CIFS incorrectly handled authentication. When a user
had a CIFS share mounted that required authentication, a local user could
mount the same share without knowing the correct password. (CVE-2011-1585)

Andrea Righi discovered a race condition in the KSM memory merging support.
If KSM was being used, a local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2183)

Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause a
denial of service. (CVE-2011-2491)

Robert Swiecki discovered that mapping extensions were incorrectly handled.
A local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2011-2496)

It was discovered that the wireless stack incorrectly verified SSID
lengths. A local attacker could exploit this to cause a denial of service
or gain root privileges. (CVE-2011-2517)");

  script_tag(name:"affected", value:"'linux-lts-backport-maverick' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-31-generic", ver:"2.6.35-31.62~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-31-generic-pae", ver:"2.6.35-31.62~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-31-server", ver:"2.6.35-31.62~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-31-virtual", ver:"2.6.35-31.62~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
