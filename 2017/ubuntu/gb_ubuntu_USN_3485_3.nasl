# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843373");
  script_cve_id("CVE-2017-15265", "CVE-2017-15299", "CVE-2017-15649", "CVE-2017-15951", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16534", "CVE-2017-16535");
  script_tag(name:"creation_date", value:"2017-11-22 06:31:53 +0000 (Wed, 22 Nov 2017)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 15:46:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-3485-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3485-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3485-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-3485-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the ALSA subsystem of
the Linux kernel when creating and deleting a port via ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-15265)

Eric Biggers discovered that the key management subsystem in the Linux
kernel did not properly restrict adding a key that already exists but is
uninstantiated. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2017-15299)

It was discovered that a race condition existed in the packet fanout
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-15649)

Eric Biggers discovered a race condition in the key management subsystem of
the Linux kernel around keys in a negative state. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-15951)

Andrey Konovalov discovered a use-after-free vulnerability in the USB
serial console driver in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-16525)

Andrey Konovalov discovered that the Ultra Wide Band driver in the Linux
kernel did not properly check for an error condition. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-16526)

Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-16527)

Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel did
not properly validate USB audio buffer descriptors. A physically proximate
attacker could use this cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16529)

Andrey Konovalov discovered that the USB unattached storage driver in the
Linux kernel contained out-of-bounds error when handling alternative
settings. A physically proximate attacker could use to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2017-16530)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB interface association descriptors. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16531)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB HID descriptors. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16533)

Andrey Konovalov discovered that the USB subsystem in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1003-aws", ver:"4.4.0-1003.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1003.3", rls:"UBUNTU14.04 LTS"))) {
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
