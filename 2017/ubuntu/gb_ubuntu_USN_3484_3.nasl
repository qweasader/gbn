# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843374");
  script_cve_id("CVE-2017-12188");
  script_tag(name:"creation_date", value:"2017-11-22 06:32:46 +0000 (Wed, 22 Nov 2017)");
  script_version("2024-04-03T05:05:20+0000");
  script_tag(name:"last_modification", value:"2024-04-03 05:05:20 +0000 (Wed, 03 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-02 18:05:18 +0000 (Tue, 02 Apr 2024)");

  script_name("Ubuntu: Security Advisory (USN-3484-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3484-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3484-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp' package(s) announced via the USN-3484-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the KVM subsystem in the Linux kernel did not
properly keep track of nested levels in guest page tables. A local attacker
in a guest VM could use this to cause a denial of service (host OS crash)
or possibly execute arbitrary code in the host OS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.10.0-1009-gcp", ver:"4.10.0-1009.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.10.0.1009.11", rls:"UBUNTU16.04 LTS"))) {
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
