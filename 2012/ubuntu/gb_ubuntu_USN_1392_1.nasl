# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840925");
  script_cve_id("CVE-2011-2182");
  script_tag(name:"creation_date", value:"2012-03-09 04:56:02 +0000 (Fri, 09 Mar 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1392-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1392-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1392-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fsl-imx51' package(s) announced via the USN-1392-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of service or
escalate privileges.");

  script_tag(name:"affected", value:"'linux-fsl-imx51' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-612-imx51", ver:"2.6.31-612.33", rls:"UBUNTU10.04 LTS"))) {
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
